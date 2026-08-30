# Shardscape

A self-hosted, multi-site, S3-compatible object store with global
content-addressed deduplication. One binary, no external database.

## What it does

Shardscape mirrors your S3-compatible object storage across multiple physical
sites linked by a VPN. Objects are chunked, content-addressed with blake3, and
deduplicated globally. Sites converge asynchronously through a last-write-wins
(LWW) fact log — no consensus protocol, no quorum, no external database.

Each site runs a single `shardscape` binary backed by an embedded SQLite store
and a local filesystem block store.

## Primary use case

You have two or more locations connected by a VPN (e.g. Tailscale). You write
to one location at a time — home, office, a travel laptop. The other sites act
as live mirrors: they replicate everything automatically and can serve reads
at any time. If you travel, any site can become the primary writer. If a site
goes offline for days or weeks, it catches up by replaying the fact log when it
returns.

This is **not** a multi-master write-scaling system. It is a cheap, self-hosted
S3 alternative designed for redundancy and availability across a small number
of sites.

## Features

- **S3-compatible API** — works with any S3 client (aws-cli, rclone, boto3, etc.)
- **Content-addressed deduplication** — identical data is stored once, globally
- **Async replication** — sites converge without consensus; no quorum needed
- **Offline-tolerant** — a site can be offline for weeks and rejoin cleanly
- **Single binary** — no external database, no external object store daemon
- **Encrypted cluster traffic** — Noise protocol (`Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s`)
- **CLI-first setup** — secrets are generated, not hand-edited; no YAML to write
- **Disk guards** — configurable free-space reserve and storage quota

## Quick start

### Build

```sh
cargo build --release
sudo install -m 0755 target/release/shardscape /usr/local/bin/shardscape
```

A static musl build is also available via `Dockerfile.static`.

### Initialize the first site

```sh
shardscape init \
  --data-dir /var/lib/shardscape \
  --location-id home \
  --s3-addr 0.0.0.0:8014 \
  --internal-addr 0.0.0.0:8015 \
  --advertise http://<this-node-vpn-ip>:8015
```

This generates the cluster secret, admin credentials, and a Noise keypair.
Save the printed secrets — they are shown only once.

### Join additional sites

On each additional machine:

```sh
shardscape join http://<seed-node-vpn-ip>:8015 \
  --secret <CLUSTER_SECRET> \
  --data-dir /var/lib/shardscape \
  --location-id office \
  --s3-addr 0.0.0.0:8014 \
  --internal-addr 0.0.0.0:8015 \
  --advertise http://<this-node-vpn-ip>:8015
```

Existing data backfills automatically once the node is running.

### Run

```sh
shardscape serve --config /var/lib/shardscape/config.toml
```

Or use the included [systemd unit](deploy/systemd/shardscape.service) for
production deployments — see the [bare-metal guide](docs/BAREMETAL.md).

### Check cluster health

```sh
shardscape status --config /var/lib/shardscape/config.toml
```

## Networking

| Port | Purpose | Notes |
|------|---------|-------|
| 8014 | S3 API | Plain HTTP. Front with a TLS proxy (Caddy, nginx) if exposed beyond localhost or the VPN. |
| 8015 | Internal cluster traffic | Noise-encrypted. Must be reachable between sites over the VPN. |

## Configuration

`shardscape init` and `shardscape join` generate a `config.toml` — see
[config.toml](config.toml) for an annotated example. Key settings:

- **Chunking**: fixed-size or content-defined (FastCDC), with configurable block sizes
- **GC**: grace period and sweep interval for the mark-and-sweep garbage collector
- **Disk guards**: `min_free_bytes` (free-space reserve) and `max_bytes` (storage quota)
- **Block backend**: local filesystem (default) or SeaweedFS

## Deployment

- **Bare metal with systemd** (recommended): [docs/BAREMETAL.md](docs/BAREMETAL.md)
- **Kubernetes**: `shardscape render-k8s` generates manifests from your config;
  sample manifests live in [deploy/k8s/](deploy/k8s/)

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — technical reference: schema, replication,
  GC, security, durability model
- [Bare-metal deployment](docs/BAREMETAL.md) — step-by-step systemd setup

## Limitations

- **No S3 object versioning** — each key holds one version, resolved by
  last-write-wins. `ListObjectVersions` is not supported.
- **LWW conflict resolution** — concurrent writes to the same key from different
  sites resolve by timestamp; there is no conflict detection or multi-version
  concurrency.
- **Single-site durability window** — a PUT is acknowledged once one site holds
  the data. If that site is lost before replication completes, the object is lost.
  The failure is logged, never silent.

## Testing

```sh
# Unit and integration tests
cargo test

# End-to-end (two real nodes on localhost, no Docker needed)
cd e2e && pip install -r requirements.txt && python run_e2e.py
```

## License

Apache 2.0
