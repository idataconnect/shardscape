# Shardscape Architecture

> This is the technical reference for the system's design.

## Overview

Shardscape is a self-hosted, multi-site, S3-compatible object store with global
content-addressed deduplication. It targets small teams and businesses with
a couple of physical sites linked over a VPN (Tailscale is the assumed substrate)
that want a cheap S3 alternative which keeps working when a site is offline —
possibly for weeks.

Each site runs **one self-contained binary** (`shardscape`). There is no external
database and no external object-storage daemon: metadata lives in an embedded
SQLite store, block bytes live in a local content-addressed filesystem store, and
sites converge through an asynchronous last-write-wins (LWW) fact log.

```
        Client (S3 / SigV4)
              │
              ▼
   ┌────────────────────────┐
   │       shardscape       │   one binary per site
   │  ┌──────────────────┐  │
   │  │ S3 API (s3s)     │  │
   │  ├──────────────────┤  │
   │  │ chunk → blake3   │  │   content-addressed dedup (FastCDC or fixed)
   │  ├──────────────────┤  │
   │  │ embedded store   │──┼──► shardscape.db   (SQLite: manifests, blocks,
   │  │ (rusqlite)       │  │                     users, nodes, fact log)
   │  ├──────────────────┤  │
   │  │ block CAS        │──┼──► blocks/aa/bb/…  (local files, hash-named)
   │  └──────────────────┘  │
   └───────────┬────────────┘
               │ /internal/*  (Noise-encrypted: facts, blocks, membership)
               ▼
        other shardscape sites
```

### The model in one paragraph

Blocks are immutable and content-addressed, so they form a **grow-only set** that
can never conflict. Object manifests (`bucket/key → [block hashes]`) are a
**per-key LWW register** resolved by a cluster-synchronised timestamp; with a
single writer almost all the time, conflicts are rare and LWW is correct. The
only genuinely hard distributed problem is garbage collection, and it reduces to
one invariant: **never delete the last copy of a block any site might still
reference.** None of this needs consensus — it needs an async fact log and a
careful garbage collector.

## Repository layout

The repo is a single Rust crate (`shardscape`) at the root, plus deploy assets:

```
Cargo.toml             Crate: shardscape (builds the `shardscape` binary)
src/
  main.rs              CLI (init/serve/join/status/render-k8s), background tasks,
                       internal Noise endpoints, peer discovery
  store.rs             Embedded SQLite store: manifests, blocks, block locations,
                       LWW fact log, replication queue, mark-and-sweep GC, nodes
  db.rs                Policy engine + shared types; re-exports Store as Db
  storage.rs           S3 trait impl, chunking pipeline, BlockStore/BlobStore,
                       cross-site fetch + read-repair, GC sweep
  chunking.rs          Fixed-size and FastCDC chunking strategies
  clock.rs             Cluster-synchronised logical clock (LWW timestamps)
  hashing.rs           Shard-id derivation, prefix key ranges
  noise_transport.rs   Noise_XXpsk3 transport for /internal/* traffic
e2e/run_e2e.py         Two-node end-to-end test (no external infrastructure)
e2e/k8s/               In-cluster multi-node tests (3-node mesh + partition/LWW)
docs/                  ARCHITECTURE.md (this file), BAREMETAL.md
deploy/k8s/            Sample manifest rendered by `shardscape render-k8s`
deploy/systemd/        Reference systemd unit
Dockerfile             glibc image (default); Dockerfile.static is musl/scratch
skaffold.yaml          Build the one image, apply the rendered manifest
```

## The node binary (`main.rs`)

### CLI — the only setup surface

No hand-edited YAML. Secrets are generated, not typed.

| Command | What it does |
|---------|--------------|
| `init` | Generate cluster secret + admin password + Noise keypair, write `config.toml`, bootstrap the admin user directly in the store. The first site. |
| `serve` | Run the node. |
| `join <peer> --secret S` | Create this site's config from flags (if absent), handshake the peer for a clock offset, register with it, then serve. Existing data backfills automatically. |
| `status` | Local health: live objects, local blocks, blocks-to-pull, pending GC, fact-log length, peers + per-peer sync cursor. |
| `render-k8s` | Emit a self-contained single-node manifest from config. Manifests are an *output*, never a hand-edited input. |

### Startup sequence (`serve`)

1. Load `config.toml`; generate + persist a Noise keypair on first boot.
2. Initialise the `ClusterClock` from the persisted offset.
3. If joining: handshake the peer (clock offset + mutual registration).
4. Open the embedded store (runs migrations).
5. Record self in the node registry; record the joined peer if any.
6. Start background tasks:
   - **Fact sync** (10 s): membership gossip, then pull + LWW-apply each peer's
     new facts.
   - **GC reaper** (`gc_interval_seconds`): recomputable mark-and-sweep.
   - **Replication drainer** (30 s): pull announced blocks this site lacks.
   - **Heartbeat** (30 s): refresh this node's own registry entry.
7. Serve the Noise internal listener and the S3 listener.

### Internal endpoints (Noise-encrypted, cluster-secret authenticated)

| Path | Purpose |
|------|---------|
| `GET /internal/cluster/config` | Cluster time + this node's identity (join + clock sync) |
| `GET /internal/facts/{after}` | This site's own-originated facts after a cursor |
| `GET /internal/nodes` | This site's full node registry (membership gossip) |
| `GET /internal/join?id=&addr=` | Register a joining peer |
| `GET /internal/blocks/{hex}` | Serve a raw block by blake3 hash (cross-site fetch) |
| `GET /internal/gc/force` | Operator-triggered stop-the-world orphan sweep |

## Embedded store (`store.rs`)

A single SQLite file per site (WAL mode). Tables: `objects` (manifests, with an
LWW `deleted` tombstone flag), `blocks` + `block_locations` (size + where each
block lives), `users`, `multipart_uploads` + `parts`, `nodes` (address registry),
`pending_deletions` (GC sweep state), `replication_queue` (blocks to pull), and
`fact_log` + `replication_cursors` (replication).

Every mutating row carries an `updated_at` micros timestamp from the cluster
clock. Writes are LWW: a row only advances when the incoming timestamp is newer.

### Distributed list

Objects are listed with one ordered index over `(bucket, key)` — globally sorted,
paginated, tombstone-filtered. (The old 64-shard k-way merge existed only because
ScyllaDB partitioned the data; SQLite needs none of it.)

## Replication — the LWW fact log

Each site keeps an append-only `fact_log` of its **own-originated** metadata
mutations. A `Fact` is one of:

- `ObjectPut` — a manifest write
- `ObjectDelete` — an LWW tombstone
- `BlockAnnounce` — "this site now holds block H (size, fid)"
- `UserPut` — an S3 credential / policy

Each mutator appends its fact in the same transaction as the local write. The
fact sync task pulls each peer's facts after a per-peer cursor and applies them
with LWW merge — **without re-logging**, since every site pulls directly from
every other (a small mesh converges with no gossip fan-out). Facts carry the
origin's timestamp, so application order doesn't affect the result.

A site offline for a week simply replays the log when it returns. No majority is
required to make progress — which is also why Raft-style stores (rqlite, etcd,
TigerBeetle) are the wrong tool here: they stall when a travelling site is
unreachable.

### Peer discovery

The node registry is an address book, not a liveness oracle. `join` exchanges
identities and registers both ends; each sync cycle also pulls peers'
`/internal/nodes` and merges, so a leaf discovers sibling leaves transitively.
Unreachable peers are simply skipped (the drainer backs off); they aren't
evicted.

## Blocks

### Storage backends (`BlobStore`)

Physical persistence is pluggable. The default is **`LocalBlob`** — each block is
a file at `blocks/aa/bb/<full-hex>`, written temp-then-rename so a reader never
sees a partial block. **`SeaweedBlob`** remains available for deployments that
want volume packing / compaction. The distributed logic lives once in
`DistributedBlockStore` over either backend.

### Write path

Chunk the body (FastCDC or fixed); for each chunk: blake3 hash; if not already
local, persist the bytes and `store_local_block` (record location + append a
`BlockAnnounce`). Then write the object manifest (`ObjectPut`).

### Read path

For each block hash in the manifest: serve from local storage if present;
otherwise look up `block_locations` (populated by replicated announces) and fetch
from a holder over `/internal/blocks/{hash}`, promoting the copy locally
(read-repair) and announcing it.

### Replication

When a site applies a `BlockAnnounce` for a block it lacks, it enqueues a
self-pull. The background drainer fetches each queued block from any announced
holder, stores it locally, and announces the new copy — so every site converges
to a full mirror. Failed pulls are rescheduled with exponential backoff (1 min
base, ×2, capped at 6 h) and never evicted, so replication converges once a
source is reachable.

## Garbage collection — recomputable mark-and-sweep

No reference counting. Each sweep recomputes the **live set**: the union of block
hashes named by any non-tombstoned manifest plus all in-progress multipart parts.
Because manifests replicate, this set is global. The sweep then:

1. **Mark.** A local block absent from the live set is recorded in
   `pending_deletions` with `not_before = now + grace`. A block that re-enters the
   live set has its pending entry cancelled.
2. **Sweep.** Past the grace period, a confirmed orphan's bytes and local location
   entry are deleted; the block row vanishes once the last site has done the same.

Because the live set is global and the grace period exceeds replication lag, an
orphan after grace is genuinely unreferenced cluster-wide — which is what makes
even last-copy deletion safe (the last-copy rule, achieved structurally
rather than by a distributed refcount). The failure modes are deliberately
lopsided: keeping an orphan too long costs a little disk; deleting a referenced
last copy is the only catastrophe, so the design biases hard toward keeping.

`shardscape`'s `/internal/gc/force` (and a future CLI fan-out) triggers an
immediate stop-the-world sweep for disk-pressure emergencies — same live-set
safety, no grace wait.

## Clock (`clock.rs`)

`ClusterClock` wraps `SystemTime` with a signed millisecond offset relative to the
cluster, applied to every LWW timestamp so causal ordering holds across sites even
as local clocks drift. The offset is computed at join (RTT/2 + peer time) and
refreshed by a background clock-sync task; it is persisted to `config.toml`.

## Security

All `/internal/*` traffic runs over a dedicated port wrapped in
`Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s` (mutual static-key auth; PSK derived from
the cluster secret), with a defence-in-depth secret header check after the
handshake. The S3 API port is plain HTTP and must sit behind a TLS-terminating
proxy when exposed beyond localhost / the VPN.

## Durability model

PUTs are acknowledged fast — once one site holds the block and the manifest is
written locally. Cross-site durability arrives asynchronously via the drainer.
This leaves a small accepted window: a block acknowledged on a single site that
dies before replication can be lost. The failure is **loud, not silent** — a read
for such a block logs an `error!` distinguishing "all holder sites down" (possible
loss) from "holders live but fetch failed" (transient). The trade-off is
intentional: cheap nodes across 2+ sites are rarely all down at once.

## Testing

- **Unit + integration tests** (`cargo test`): store LWW/convergence/tombstones,
  mark-and-sweep GC (live-set safety, grace, force, cancel), local-CAS round-trip,
  the chunking pipeline, the policy engine, and the S3 object/multipart paths.
- **End-to-end** (`e2e/run_e2e.py`): spins up two real nodes on localhost
  (no Docker, no external services), joins them, and asserts cross-site read,
  bidirectional replication, and LWW-tombstone deletion over the real Noise
  transport.

## Known limitations

- **LWW only** — concurrent writes to the same key resolve by timestamp; no
  multi-version concurrency or conflict detection.
- **Fast-PUT durability window** — see above; an accepted, observable trade.
- **Block replication mirrors everything** — every site pulls every block. Good
  for the multi-site mirror goal; not a partial-replication / tiering design.
- **`max_keys` unbounded; list truncation may over-report** — `is_truncated` errs
  toward a spurious empty trailing page rather than ever under-reporting.
- **Wildcard policy matching** — only `prefix*` suffix wildcards; mid-string
  wildcards never match.
