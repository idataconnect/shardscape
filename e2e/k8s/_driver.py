#!/usr/bin/env python3
"""S3-level driver for the in-cluster multi-node tests. Invoked by
test_multinode.sh with port-forwards already established.

  _driver.py mesh      <secret> <portA> <portC>
  _driver.py partition <secret> <portA> <portB> <namespace>
"""
import subprocess
import sys
import time

import boto3
from botocore.config import Config


def cli(port, secret):
    return boto3.client(
        "s3", endpoint_url=f"http://127.0.0.1:{port}",
        aws_access_key_id="admin", aws_secret_access_key=secret, region_name="us-east-1",
        config=Config(s3={"addressing_style": "path"}, signature_version="s3v4",
                      retries={"max_attempts": 1}))


def poll(fn, what, timeout=120):
    end, last = time.time() + timeout, None
    while time.time() < end:
        try:
            if fn():
                return
        except Exception as e:  # noqa: BLE001
            last = e
        time.sleep(2)
    raise AssertionError(f"timeout waiting for {what}: {last}")


def get(c, key, bucket="ssbucket"):
    try:
        return c.get_object(Bucket=bucket, Key=key)["Body"].read()
    except Exception:  # noqa: BLE001
        return None


def mesh(secret, port_a, port_c):
    A, C = cli(port_a, secret), cli(port_c, secret)
    A.create_bucket(Bucket="ssbucket")
    va = b"written-at-A" * 40
    A.put_object(Bucket="ssbucket", Key="from-a", Body=va)
    poll(lambda: get(C, "from-a") == va, "A->C")
    vc = b"written-at-C" * 40
    C.put_object(Bucket="ssbucket", Key="from-c", Body=vc)
    poll(lambda: get(A, "from-c") == vc, "C->A")


def partition(secret, port_a, port_b, ns):
    A, B = cli(port_a, secret), cli(port_b, secret)

    def patch(svc, app):
        subprocess.run(
            ["kubectl", "-n", ns, "patch", "svc", svc, "-p",
             '{"spec":{"selector":{"app":"%s"}}}' % app],
            check=True, capture_output=True)

    A.create_bucket(Bucket="ssbucket")
    A.put_object(Bucket="ssbucket", Key="base", Body=b"baseline")
    poll(lambda: get(B, "base") == b"baseline", "baseline A->B")

    # Sever A<->B: with no matching endpoints, sync dials the Service DNS and
    # fails. Pod port-forwards still let us write to each side.
    patch("shardscape-a", "partitioned")
    patch("shardscape-b", "partitioned")
    time.sleep(12)

    A.put_object(Bucket="ssbucket", Key="k", Body=b"A-WROTE-THIS")
    time.sleep(2)  # B's write is strictly later -> newer LWW timestamp
    B.put_object(Bucket="ssbucket", Key="k", Body=b"B-WROTE-THIS-LATER")
    time.sleep(12)  # if the partition leaked, they'd converge here — they must not
    assert get(A, "k") == b"A-WROTE-THIS", f"A lost its own write: {get(A,'k')}"
    assert get(B, "k") == b"B-WROTE-THIS-LATER", f"B lost its own write: {get(B,'k')}"

    # Heal and require both to converge on the newer write.
    patch("shardscape-a", "shardscape")
    patch("shardscape-b", "shardscape")
    poll(lambda: get(A, "k") == b"B-WROTE-THIS-LATER" and get(B, "k") == b"B-WROTE-THIS-LATER",
         "LWW convergence to newer write")


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "mesh":
        mesh(sys.argv[2], sys.argv[3], sys.argv[4])
    elif mode == "partition":
        partition(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        sys.exit(f"unknown mode {mode}")
    print(f"[{mode}] ok")
