#!/usr/bin/env python3
"""End-to-end test for Shardscape: two live nodes, no external infrastructure.

Because the rearchitecture replaced ScyllaDB + SeaweedFS with an embedded SQLite
store and a local-filesystem block CAS, a full two-site cluster is just two
processes on localhost. This exercises every phase end to end:

  * Phase 1/4: embedded store + local block CAS (a node serves S3 at all)
  * Phase 2:   LWW fact-log sync over Noise (manifests cross sites)
  * discovery: join handshake + membership gossip (nodes find each other)
  * blocks:    cross-site fetch / read-repair (B serves bytes written to A)
  * Phase 3:   LWW tombstones (a delete on A removes the object on B)
  * Phase 5:   the CLI (init / join) is the only setup surface

Run:  e2e/run_e2e.py [path-to-shardscape-binary]
Exits non-zero on any failure.
"""
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# e2e/ lives inside the repo; the binary is built under target.
SS_API = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(SS_API, "target", "debug", "shardscape")

A_S3, A_INT = 8014, 8015
B_S3, B_INT = 8024, 8025
DEADLINE = 30  # seconds to allow async convergence


def wait_port(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    raise TimeoutError(f"port {port} never opened")


def s3_client(port, secret):
    return boto3.client(
        "s3",
        endpoint_url=f"http://127.0.0.1:{port}",
        aws_access_key_id="admin",
        aws_secret_access_key=secret,
        region_name="us-east-1",
        config=Config(s3={"addressing_style": "path"}, signature_version="s3v4",
                      retries={"max_attempts": 1}),
    )


def poll(fn, what, deadline=DEADLINE):
    """Retry fn() until it returns truthy or deadline; returns the value or raises."""
    end = time.time() + deadline
    last = None
    while time.time() < end:
        try:
            v = fn()
            if v:
                return v
        except Exception as e:  # noqa: BLE001
            last = e
        time.sleep(1)
    raise AssertionError(f"timed out waiting for: {what} (last error: {last})")


def main():
    if not os.path.exists(BIN):
        print(f"binary not found: {BIN}\nbuild it: (cargo build)", file=sys.stderr)
        return 1

    work = tempfile.mkdtemp(prefix="ss-e2e-")
    a_dir, b_dir = os.path.join(work, "A"), os.path.join(work, "B")
    os.makedirs(a_dir)
    os.makedirs(b_dir)
    procs = []
    try:
        # ── init site A (CLI generates secrets) ──────────────────────────────
        out = subprocess.run(
            [BIN, "init", "--config", os.path.join(a_dir, "config.toml"),
             "--location-id", "home", "--data-dir", os.path.join(a_dir, "data"),
             "--s3-addr", f"0.0.0.0:{A_S3}", "--internal-addr", f"0.0.0.0:{A_INT}",
             "--advertise", f"http://127.0.0.1:{A_INT}"],
            capture_output=True, text=True, check=True,
        ).stdout
        secret = re.search(r"Admin secret key:\s+(\S+)", out).group(1)
        cluster = re.search(r"Cluster secret:\s+(\S+)", out).group(1)
        print(f"[init] site A ready; admin secret + cluster secret captured")

        # ── serve A ──────────────────────────────────────────────────────────
        procs.append(subprocess.Popen(
            [BIN, "serve", "--config", os.path.join(a_dir, "config.toml")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        wait_port(A_S3)
        print("[serve] site A up")

        # ── join site B (CLI creates its config from flags + joins A) ────────
        procs.append(subprocess.Popen(
            [BIN, "join", f"http://127.0.0.1:{A_INT}", "--secret", cluster,
             "--config", os.path.join(b_dir, "config.toml"),
             "--location-id", "office", "--data-dir", os.path.join(b_dir, "data"),
             "--s3-addr", f"0.0.0.0:{B_S3}", "--internal-addr", f"0.0.0.0:{B_INT}",
             "--advertise", f"http://127.0.0.1:{B_INT}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        wait_port(B_S3)
        print("[join] site B up and joined")

        a = s3_client(A_S3, secret)
        b = s3_client(B_S3, secret)

        # ── admin replicated to B? (user_put fact) — proves auth converges ───
        a.create_bucket(Bucket="vault")
        body = b"the quick brown fox jumps over the lazy dog" * 50  # ~2KB, 1 block
        a.put_object(Bucket="vault", Key="a/one.txt", Body=body)
        print("[write] PUT vault/a/one.txt on A")

        # ── object + block converge to B (fact sync + cross-site fetch) ──────
        def read_b():
            return b.get_object(Bucket="vault", Key="a/one.txt")["Body"].read()
        got = poll(read_b, "object readable on B")
        assert got == body, "B returned wrong bytes"
        print("[sync] B serves the object written to A  ✓")

        # ── reverse direction: write on B, read on A ─────────────────────────
        body2 = b"a second object, written at the office" * 30
        b.put_object(Bucket="vault", Key="b/two.txt", Body=body2)
        got2 = poll(lambda: a.get_object(Bucket="vault", Key="b/two.txt")["Body"].read(),
                    "B's object readable on A")
        assert got2 == body2
        print("[sync] A serves the object written to B  ✓")

        # ── head_bucket ──────────────────────────────────────────────────────
        a.head_bucket(Bucket="vault")
        print("[s3]   head_bucket on A  ✓")

        # ── list_objects v1 ─────────────────────────────────────────────────
        resp = a.list_objects(Bucket="vault")
        keys_v1 = [o["Key"] for o in resp.get("Contents", [])]
        assert "a/one.txt" in keys_v1 and "b/two.txt" in keys_v1, f"list_objects v1 missing keys: {keys_v1}"
        print("[s3]   list_objects v1  ✓")

        # ── copy_object ─────────────────────────────────────────────────────
        a.copy_object(Bucket="vault", Key="a/one_copy.txt",
                       CopySource="vault/a/one.txt")
        got_copy = a.get_object(Bucket="vault", Key="a/one_copy.txt")["Body"].read()
        assert got_copy == body, "copy_object returned wrong bytes"
        print("[s3]   copy_object on A  ✓")

        # verify the copy converges to B
        got_copy_b = poll(
            lambda: b.get_object(Bucket="vault", Key="a/one_copy.txt")["Body"].read(),
            "copied object readable on B")
        assert got_copy_b == body
        print("[sync] copy_object converged to B  ✓")

        # ── multipart upload ────────────────────────────────────────────────
        mp_body = os.urandom(2 * 1024 * 1024)  # 2 MiB, split into 2 × 1 MiB parts
        part_size = 1024 * 1024
        mp = a.create_multipart_upload(Bucket="vault", Key="multi/big.bin")
        upload_id = mp["UploadId"]
        print(f"[mp]   create_multipart_upload → {upload_id}")

        parts = []
        for i in range(2):
            chunk = mp_body[i * part_size : (i + 1) * part_size]
            resp = a.upload_part(Bucket="vault", Key="multi/big.bin",
                                 UploadId=upload_id, PartNumber=i + 1, Body=chunk)
            parts.append({"ETag": resp["ETag"], "PartNumber": i + 1})
        print("[mp]   uploaded 2 parts")

        # list_parts
        lp = a.list_parts(Bucket="vault", Key="multi/big.bin", UploadId=upload_id)
        assert len(lp["Parts"]) == 2, f"list_parts expected 2, got {len(lp['Parts'])}"
        print("[mp]   list_parts  ✓")

        # list_multipart_uploads
        lmu = a.list_multipart_uploads(Bucket="vault")
        ids = [u["UploadId"] for u in lmu.get("Uploads", [])]
        assert upload_id in ids, f"list_multipart_uploads missing {upload_id}: {ids}"
        print("[mp]   list_multipart_uploads  ✓")

        # complete
        a.complete_multipart_upload(
            Bucket="vault", Key="multi/big.bin", UploadId=upload_id,
            MultipartUpload={"Parts": parts})
        got_mp = a.get_object(Bucket="vault", Key="multi/big.bin")["Body"].read()
        assert got_mp == mp_body, f"multipart body mismatch: expected {len(mp_body)}, got {len(got_mp)}"
        print("[mp]   complete_multipart_upload  ✓")

        # verify multipart object converges to B
        got_mp_b = poll(
            lambda: b.get_object(Bucket="vault", Key="multi/big.bin")["Body"].read(),
            "multipart object readable on B")
        assert got_mp_b == mp_body
        print("[sync] multipart object converged to B  ✓")

        # ── abort_multipart_upload ──────────────────────────────────────────
        mp2 = a.create_multipart_upload(Bucket="vault", Key="multi/aborted.bin")
        a.upload_part(Bucket="vault", Key="multi/aborted.bin",
                      UploadId=mp2["UploadId"], PartNumber=1, Body=b"junk")
        a.abort_multipart_upload(Bucket="vault", Key="multi/aborted.bin",
                                  UploadId=mp2["UploadId"])
        lmu2 = a.list_multipart_uploads(Bucket="vault")
        ids2 = [u["UploadId"] for u in lmu2.get("Uploads", [])]
        assert mp2["UploadId"] not in ids2, "aborted upload still listed"
        print("[mp]   abort_multipart_upload  ✓")

        # ── upload_part_copy ────────────────────────────────────────────────
        mp3 = a.create_multipart_upload(Bucket="vault", Key="multi/copied.bin")
        a.upload_part_copy(Bucket="vault", Key="multi/copied.bin",
                           UploadId=mp3["UploadId"], PartNumber=1,
                           CopySource="vault/multi/big.bin",
                           CopySourceRange=f"bytes=0-{part_size - 1}")
        a.upload_part_copy(Bucket="vault", Key="multi/copied.bin",
                           UploadId=mp3["UploadId"], PartNumber=2,
                           CopySource="vault/multi/big.bin",
                           CopySourceRange=f"bytes={part_size}-{2 * part_size - 1}")
        lp3 = a.list_parts(Bucket="vault", Key="multi/copied.bin",
                           UploadId=mp3["UploadId"])
        copy_parts = [{"ETag": p["ETag"], "PartNumber": p["PartNumber"]}
                      for p in lp3["Parts"]]
        a.complete_multipart_upload(
            Bucket="vault", Key="multi/copied.bin", UploadId=mp3["UploadId"],
            MultipartUpload={"Parts": copy_parts})
        got_copy_mp = a.get_object(Bucket="vault", Key="multi/copied.bin")["Body"].read()
        assert got_copy_mp == mp_body, "upload_part_copy body mismatch"
        print("[mp]   upload_part_copy + complete  ✓")

        # ── LWW tombstone: delete on A removes it on B ───────────────────────
        a.delete_object(Bucket="vault", Key="a/one.txt")
        print("[write] DELETE vault/a/one.txt on A")

        def gone_on_b():
            try:
                b.get_object(Bucket="vault", Key="a/one.txt")
                return False
            except ClientError as e:
                return e.response["Error"]["Code"] in ("NoSuchKey", "404")
        poll(gone_on_b, "tombstone propagated to B")
        print("[gc]   delete on A tombstoned the object on B  ✓")

        print("\nE2E PASSED")
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"\nE2E FAILED: {e}", file=sys.stderr)
        return 1
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
