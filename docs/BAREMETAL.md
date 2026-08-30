# Bare-metal deployment (the recommended path)

Shardscape is a single binary with no external database or object-store daemon,
so the simplest — and recommended — deployment is one process per site, managed
by systemd. No Kubernetes, no ingress. If your sites are linked by a VPN at the
router level, each box can reach the others directly and nothing else is needed.

The Kubernetes manifests (`shardscape render-k8s`, `deploy/k8s/`) exist for people
already running k8s; they are not required.

## 0. Install the binary on every site

Build the glibc binary (or grab the static musl one — see `Dockerfile.static`) and
install it as `shardscape`:

```sh
cargo build --release
sudo install -m 0755 target/release/shardscape /usr/local/bin/shardscape
sudo useradd --system --no-create-home shardscape   # once per host
```

## 1. First site (the seed)

`init` generates the cluster secret, the admin credentials, and the Noise keypair,
and bootstraps the admin user. It prints the secrets **once** — save them.

```sh
sudo -u shardscape shardscape init \
  --config /var/lib/shardscape/config.toml \
  --data-dir /var/lib/shardscape \
  --location-id home \
  --s3-addr 0.0.0.0:8014 \
  --internal-addr 0.0.0.0:8015 \
  --advertise http://10.0.0.1:8015        # this box's VPN-reachable address
```

Then enable the service:

```sh
sudo cp deploy/systemd/shardscape.service /etc/systemd/system/
sudo systemctl enable --now shardscape
```

## 2. Additional sites (join)

On each other box, `join` creates that site's config from the flags using the
shared cluster secret and connects to a peer. Existing data backfills
automatically once it is serving.

```sh
sudo -u shardscape shardscape join http://10.0.0.1:8015 \
  --secret <CLUSTER_SECRET_FROM_STEP_1> \
  --config /var/lib/shardscape/config.toml \
  --data-dir /var/lib/shardscape \
  --location-id office \
  --s3-addr 0.0.0.0:8014 \
  --internal-addr 0.0.0.0:8015 \
  --advertise http://10.0.0.2:8015        # this box's VPN-reachable address

sudo cp deploy/systemd/shardscape.service /etc/systemd/system/
sudo systemctl enable --now shardscape
```

Add as many sites as you like; membership gossips so they all discover each other.

## 3. Networking

| Port | Who needs it | Notes |
|------|--------------|-------|
| 8015 | other sites  | Internal Noise traffic. Open **between sites** over the VPN. |
| 8014 | local S3 clients | Plain HTTP. Put a TLS-terminating reverse proxy (Caddy/nginx) in front if exposed beyond the LAN — TLS is intentionally *not* built into the binary. |

Set `--advertise` to each node's VPN-reachable address (`http://<vpn-ip-or-host>:8015`).

## 4. Operating

```sh
shardscape status --config /var/lib/shardscape/config.toml   # objects, blocks, peers, sync cursors
journalctl -u shardscape -f                                  # logs
```

A site can be offline for days and rejoin cleanly — it replays the fact log and
re-pulls any blocks it missed. To reclaim space immediately on a node under disk
pressure, an operator can trigger the stop-the-world orphan sweep (the
`/internal/gc/force` endpoint); otherwise GC runs automatically on a grace-period
schedule.
