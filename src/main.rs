use s3s::service::S3ServiceBuilder;
use std::sync::Arc;
use tracing::{info, error, warn};
use std::net::SocketAddr;
use clap::Parser;
use hyper::{Request, Response, StatusCode, body::Incoming};
use http_body_util::Full;
use bytes::Bytes;
use serde::{Serialize, Deserialize};
use hyper::service::Service;
use std::time::Duration;
use tokio::net::TcpStream;

mod chunking;
mod config;
mod db;
mod hashing;
mod storage;
mod store;
mod disk;
mod clock;
mod noise_transport;

use noise_transport::{NoiseStream, derive_psk, decode_private_key, generate_private_key};

#[derive(Parser, Debug)]
#[command(name = "shardscape", author, version, about = "Self-hosted multi-site S3 with global dedup", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Initialise a brand-new site: generate secrets + config and bootstrap the
    /// admin user. The first site in a cluster. No YAML editing required.
    Init(InitArgs),
    /// Run the node.
    Serve {
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    /// Join an existing cluster via a peer's internal address, then run the node.
    /// If the config file doesn't exist it is created from the flags below using
    /// the given secret (no admin bootstrap — admin replicates in). Existing data
    /// backfills automatically once serving (fact-log sync).
    Join {
        /// Peer internal address, e.g. http://other-site:8015
        peer: String,
        /// The cluster secret (shared across all sites).
        #[arg(long)]
        secret: String,
        #[arg(short, long, default_value = "config.toml")]
        config: String,
        #[command(flatten)]
        site: SiteArgs,
    },
    /// Print local cluster, replication, and GC health.
    Status {
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    /// Render Kubernetes manifests for this node to stdout (or a directory).
    /// Manifests are an output of config — never a hand-edited input.
    RenderK8s {
        #[arg(short, long, default_value = "config.toml")]
        config: String,
        /// Write manifests here instead of stdout.
        #[arg(short, long)]
        out: Option<String>,
    },
}

#[derive(clap::Args, Debug)]
struct InitArgs {
    #[arg(short, long, default_value = "config.toml")]
    config: String,
    /// Use this cluster secret instead of generating one. For bringing up the
    /// first node of a cluster whose secret is managed externally (e.g. a k8s
    /// Secret shared with the sites that will join).
    #[arg(long)]
    cluster_secret: Option<String>,
    #[command(flatten)]
    site: SiteArgs,
}

/// Site-shape flags shared by `init` and `join`.
#[derive(clap::Args, Debug)]
struct SiteArgs {
    /// Unique id for this site (e.g. "home", "office").
    #[arg(long, default_value = "site-a")]
    location_id: String,
    /// S3 API bind address.
    #[arg(long, default_value = "0.0.0.0:8014")]
    s3_addr: String,
    /// Internal (Noise) bind address for cluster traffic.
    #[arg(long, default_value = "0.0.0.0:8015")]
    internal_addr: String,
    /// Address peers use to reach this node's internal port.
    #[arg(long, default_value = "http://localhost:8015")]
    advertise: String,
    /// Directory for this site's metadata DB and block storage.
    #[arg(long, default_value = ".")]
    data_dir: String,
}

/// Builds a site config from `site` flags and a cluster secret, generating a
/// fresh Noise keypair. Shared by `init` (random secret) and `join` (given one).
fn build_site_config(site: &SiteArgs, cluster_secret: String) -> anyhow::Result<config::Config> {
    let data_dir = std::path::PathBuf::from(&site.data_dir);
    std::fs::create_dir_all(&data_dir)?;
    let mut config = config::Config::default();
    config.server.s3_bind_addr = site.s3_addr.clone();
    config.server.internal_bind_addr = site.internal_addr.clone();
    config.server.advertise_addr = site.advertise.clone();
    config.server.cluster_secret = cluster_secret;
    config.server.noise_private_key = generate_private_key()?;
    config.server.clock_offset_ms = 0;
    config.database.db_path = data_dir.join("shardscape.db").to_string_lossy().into_owned();
    config.storage.local_location_id = site.location_id.clone();
    config.storage.backend = config::BlockBackend::Local {
        path: data_dir.join("blocks").to_string_lossy().into_owned(),
    };
    Ok(config)
}

#[derive(Serialize, Deserialize, Debug)]
struct ClusterConfigResponse {
    cluster_time_micros: i64,
    /// The responding node's identity, so a joiner can register it as a peer.
    #[serde(default)]
    location_id: String,
    #[serde(default)]
    advertise_addr: String,
}

/// Max facts returned per `/internal/facts` page; the puller loops on full pages
/// so a large backlog drains across several requests.
const FACT_SYNC_BATCH: i64 = 500;
/// How often the fact-sync task pulls new facts from each live peer.
const FACT_SYNC_INTERVAL_SECS: u64 = 10;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match cli.command {
        Command::Init(args) => run_init(args).await,
        Command::Serve { config } => run_server(config, None, None).await,
        Command::Join { peer, secret, config, site } => {
            // Create the joining site's config from flags if it doesn't exist yet
            // (no admin bootstrap — the admin user replicates in from the cluster).
            if !std::path::Path::new(&config).exists() {
                let cfg = build_site_config(&site, secret.clone())?;
                cfg.save(&config)?;
                info!("Wrote new site config to {}", config);
            }
            run_server(config, Some(peer), Some(secret)).await
        }
        Command::Status { config } => run_status(config).await,
        Command::RenderK8s { config, out } => run_render_k8s(config, out).await,
    }
}

async fn run_server(
    config_path: String,
    join: Option<String>,
    secret_override: Option<String>,
) -> anyhow::Result<()> {
    let mut config = config::Config::load(&config_path).unwrap_or_else(|e| {
        warn!("Config file not found or invalid at {}: {}. Using defaults.", config_path, e);
        config::Config::default()
    });

    if let Some(secret) = secret_override {
        config.server.cluster_secret = secret;
    }

    // Generate a noise keypair on first boot and persist it.
    if config.server.noise_private_key.is_empty() {
        let key = generate_private_key()?;
        info!("Generated new Noise keypair — persisting to {}", config_path);
        config.server.noise_private_key = key;
        config.save(&config_path)?;
    }
    let noise_private_key = decode_private_key(&config.server.noise_private_key)?;
    let psk = derive_psk(&config.server.cluster_secret);

    info!("Starting shardscape node ({})", config.storage.local_location_id);

    let clock = Arc::new(clock::ClusterClock::new(config.server.clock_offset_ms));
    if config.server.clock_offset_ms != 0 {
        info!("Initialized clock with offset: {}ms", config.server.clock_offset_ms);
    }

    // Persistent Join Handshake
    let joined_peer = if let Some(peer_url) = join {
        info!("Joining cluster via {}...", peer_url);
        let peer = perform_join_handshake(&peer_url, &mut config, &clock, &config_path, &noise_private_key, &psk).await?;
        info!("Joined cluster; existing data will backfill via fact-log sync.");
        Some(peer)
    } else {
        None
    };

    let db = Arc::new(db::Db::new(
        &config.database.db_path,
        config.storage.local_location_id.clone(),
        clock.clone()
    ).await?);

    // Record self + (if we just joined) the peer we joined, so the fact-sync and
    // membership-gossip tasks have somewhere to start.
    db.register_node(&config.server.advertise_addr).await?;
    if let Some((peer_id, peer_url)) = joined_peer {
        db.record_peer(&peer_id, &peer_url).await?;
    }

    // Optional env-based admin bootstrap (the CLI's `init` is the primary path;
    // a joined node receives the admin user via fact-log replication).
    if std::env::var("SS_ADMIN_PASSWORD").is_ok() {
        bootstrap_admin_user(&db).await?;
    }

    let backend = Arc::new(storage::StorageBackend::new(db.clone(), config.clone()));

    // Disk write guard: keep a free-space reserve and/or cap total usage.
    if backend.disk_guard.enabled() {
        // Seed the usage cache before the first write check.
        if backend.disk_guard.quota_enabled() {
            let usage = db.local_block_bytes().await.unwrap_or(0);
            backend.disk_guard.set_local_usage(usage as u64);
        }
        let mut parts = Vec::new();
        if backend.disk_guard.free_space_enabled() {
            parts.push(format!("reserve {}", disk::format_bytes(backend.disk_guard.min_free_bytes())));
        }
        if backend.disk_guard.quota_enabled() {
            parts.push(format!(
                "cap {} ({} used now)",
                disk::format_bytes(backend.disk_guard.max_bytes()),
                disk::format_bytes(backend.disk_guard.local_usage()),
            ));
        }
        if backend.disk_guard.free_space_enabled() {
            parts.push(format!("{} free now", disk::format_bytes(backend.disk_guard.free_bytes())));
        }
        info!("Disk write guard: {}", parts.join(", "));
        backend.disk_guard.spawn_refresher(Duration::from_secs(15));
    }

    // --- Background Tasks ---

    // 1. Adaptive Peer-to-Peer Clock Sync
    let clock_sync_db = db.clone();
    let clock_sync_clock = clock.clone();
    let clock_sync_config = config.clone();
    let clock_sync_key = noise_private_key.clone();
    let clock_sync_psk = psk;
    tokio::spawn(async move {
        let interval = Duration::from_secs(300);
        loop {
            tokio::time::sleep(interval).await;
            match clock_sync_db.get_peers().await {
                Ok(peers) if !peers.is_empty() => {
                    let peer = {
                        use rand::seq::SliceRandom;
                        peers.choose(&mut rand::thread_rng()).cloned()
                    };
                    if let Some((id, url)) = peer {
                        match refresh_clock_offset(&url, &clock_sync_config, &clock_sync_clock, &clock_sync_key, &clock_sync_psk).await {
                            Ok(_) => peer_link_ok(&id),
                            Err(e) => peer_link_failed(&id, "clock sync", e),
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => error!("Failed to fetch peers for clock sync: {}", e),
            }
        }
    });

    // 2. Fact-log sync — pull each live peer's new metadata facts and apply them
    //    with LWW merge. This is what replaces ScyllaDB's cross-site replication:
    //    object manifests, tombstones, block announcements, and users converge
    //    asynchronously, with no quorum and no repair.
    let fact_db = db.clone();
    let fact_secret = config.server.cluster_secret.clone();
    let fact_key = noise_private_key.clone();
    let fact_psk = psk;
    tokio::spawn(async move {
        let interval = Duration::from_secs(FACT_SYNC_INTERVAL_SECS);
        loop {
            tokio::time::sleep(interval).await;
            match fact_db.get_peers_with_urls().await {
                Ok(peers) if !peers.is_empty() => {
                    // Discover new members first, then pull facts (including from
                    // anyone we just learned about).
                    gossip_membership(&fact_db, &peers, &fact_secret, &fact_key, &fact_psk).await;
                    let peers = fact_db.get_peers_with_urls().await.unwrap_or(peers);
                    sync_facts_once(&fact_db, peers, &fact_secret, &fact_key, &fact_psk).await;
                }
                Ok(_) => {}
                Err(e) => error!("Fact sync: failed to fetch peers: {}", e),
            }
        }
    });

    // 3. GC Reaper
    let gc_backend = backend.clone();
    let gc_config = config.clone();
    tokio::spawn(async move {
        let interval = Duration::from_secs(gc_config.storage.gc_interval_seconds);
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = gc_backend.reap_orphaned_blocks().await {
                error!("GC Reap error: {}", e);
            }
        }
    });

    // 4. Usage cache refresher (disk guard quota check)
    if backend.disk_guard.quota_enabled() {
        let guard = backend.disk_guard.clone();
        let usage_db = db.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await;
                match usage_db.local_block_bytes().await {
                    Ok(bytes) => guard.set_local_usage(bytes as u64),
                    Err(e) => error!("Usage cache refresh failed: {e}"),
                }
            }
        });
    }

    // 5. Replication Queue Drainer
    let repl_backend = backend.clone();
    tokio::spawn(async move {
        let interval = Duration::from_secs(30);
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = repl_backend.drain_replication_queue().await {
                error!("Replication drain error: {}", e);
            }
        }
    });

    // --- S3 Service ---
    // (self already registered above, right after the store opened)
    let db_heartbeat = Arc::clone(&db);
    let advertise_addr_heartbeat = config.server.advertise_addr.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Err(e) = db_heartbeat.register_node(&advertise_addr_heartbeat).await {
                tracing::error!("Heartbeat failed: {}", e);
            }
        }
    });

    let mut service = S3ServiceBuilder::new((*backend).clone());
    service.set_auth(storage::ShardscapeAuth { db: Arc::clone(&db) });
    let s3 = service.build();
    let s3_shared = Arc::new(s3.into_shared());

    // --- Internal listener (Noise-encrypted) ---
    let internal_addr: SocketAddr = config.server.internal_bind_addr.parse()?;
    let internal_listener = tokio::net::TcpListener::bind(&internal_addr).await?;
    info!("Starting internal (Noise) server on {}", internal_addr);

    let internal_secret = config.server.cluster_secret.clone();
    let internal_clock = clock.clone();
    let internal_backend = backend.clone();
    let internal_key = noise_private_key.clone();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match internal_listener.accept().await {
                Ok(s) => s,
                Err(e) => { error!("Internal accept error: {e}"); continue; }
            };
            let secret = internal_secret.clone();
            let clock_ref = internal_clock.clone();
            let backend_ref = internal_backend.clone();
            let key = internal_key.clone();
            let psk_ref = psk;

            tokio::spawn(async move {
                let noise_stream = match NoiseStream::accept(stream, &key, &psk_ref).await {
                    Ok(s) => s,
                    Err(e) => { warn!("Noise handshake failed: {e}"); return; }
                };
                let io = hyper_util::rt::TokioIo::new(noise_stream);

                let service_fn = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let secret = secret.clone();
                    let clock_ref = clock_ref.clone();
                    let backend_inner = backend_ref.clone();
                    async move {
                        handle_internal_request(req, &secret, &clock_ref, &backend_inner).await
                    }
                });

                if let Err(err) = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, service_fn)
                    .await
                {
                    error!("Internal connection error: {}", err);
                }
            });
        }
    });

    // --- S3 listener (plain HTTP) ---
    let s3_addr: SocketAddr = config.server.s3_bind_addr.parse()?;
    let s3_listener = tokio::net::TcpListener::bind(&s3_addr).await?;
    info!("Starting S3 server on {}", s3_addr);

    loop {
        let (stream, _) = s3_listener.accept().await?;
        let io = hyper_util::rt::TokioIo::new(stream);
        let svc = s3_shared.clone();

        tokio::spawn(async move {
            let service_fn = hyper::service::service_fn(move |req: Request<Incoming>| {
                let svc = svc.clone();
                async move {
                    let res: Response<s3s::Body> = svc.call(req).await?;
                    Ok::<_, anyhow::Error>(res)
                }
            });
            if let Err(err) = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, service_fn)
                .await
            {
                error!("S3 connection error: {}", err);
            }
        });
    }
}

async fn handle_internal_request(
    req: Request<Incoming>,
    secret: &str,
    clock: &clock::ClusterClock,
    backend: &storage::StorageBackend,
) -> anyhow::Result<Response<http_body_util::Either<Full<Bytes>, s3s::Body>>> {
    // After noise, we still check the secret header as a defence-in-depth
    // sanity check (protects against misconfigured noise keys letting a
    // wrong peer in).
    let provided_secret = req.headers()
        .get("X-Shardscape-Secret")
        .and_then(|h| h.to_str().ok());

    if provided_secret != Some(secret) {
        warn!("Internal request missing or wrong secret (post-noise)");
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(http_body_util::Either::Left(Full::new(Bytes::from("Unauthorized"))))
            .unwrap());
    }

    if req.uri().path() == "/internal/cluster/config" {
        let config_resp = ClusterConfigResponse {
            cluster_time_micros: clock.now_micros(),
            location_id: backend.config.storage.local_location_id.clone(),
            advertise_addr: backend.config.server.advertise_addr.clone(),
        };
        let body = match serde_json::to_vec(&config_resp) {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to serialize cluster config: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(http_body_util::Either::Left(Full::new(Bytes::from("Internal error"))))
                    .unwrap());
            }
        };
        return Ok(Response::builder()
            .header("Content-Type", "application/json")
            .body(http_body_util::Either::Left(Full::new(Bytes::from(body))))
            .unwrap());
    }

    // Membership: return every node this site knows, so peers gossip to a
    // converged view of the mesh.
    if req.uri().path() == "/internal/nodes" {
        let nodes = match &backend.db {
            Some(db) => db.all_nodes().await.unwrap_or_default(),
            None => Vec::new(),
        };
        let body = serde_json::to_vec(&nodes).unwrap_or_default();
        return Ok(Response::builder()
            .header("Content-Type", "application/json")
            .body(http_body_util::Either::Left(Full::new(Bytes::from(body))))
            .unwrap());
    }

    // A joining node registers itself here: /internal/join?id=<loc>&addr=<url>.
    if req.uri().path() == "/internal/join" {
        let (mut id, mut addr) = (String::new(), String::new());
        if let Some(q) = req.uri().query() {
            for (k, v) in url_query_pairs(q) {
                match k.as_str() {
                    "id" => id = v,
                    "addr" => addr = v,
                    _ => {}
                }
            }
        }
        if let (Some(db), false) = (&backend.db, id.is_empty() || addr.is_empty()) {
            if let Err(e) = db.record_peer(&id, &addr).await {
                error!("Failed to record joining peer {id}: {e}");
            } else {
                info!("Registered joining peer {id} at {addr}");
            }
        }
        return Ok(Response::builder()
            .body(http_body_util::Either::Left(Full::new(Bytes::from("ok"))))
            .unwrap());
    }

    // Fact-log pull: a peer asks for our own-originated facts after its cursor.
    // Path: /internal/facts/{after_seq}. We return up to FACT_SYNC_BATCH facts as
    // JSON; the puller loops until it receives a short page.
    if let Some(after_str) = req.uri().path().strip_prefix("/internal/facts/") {
        let after: i64 = after_str.parse().unwrap_or(0);
        let facts = match &backend.db {
            Some(db) => db.facts_since(after, FACT_SYNC_BATCH).await.unwrap_or_default(),
            None => Vec::new(),
        };
        let body = match serde_json::to_vec(&facts) {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to serialize facts: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(http_body_util::Either::Left(Full::new(Bytes::from("Internal error"))))
                    .unwrap());
            }
        };
        return Ok(Response::builder()
            .header("Content-Type", "application/json")
            .body(http_body_util::Either::Left(Full::new(Bytes::from(body))))
            .unwrap());
    }

    // Operator-triggered stop-the-world orphan sweep (disk pressure). Reaps
    // confirmed orphans immediately, skipping the grace wait — still never
    // touches a block in the live set. The CLI fans this out to every member.
    if req.uri().path() == "/internal/gc/force" {
        match backend.force_sweep_orphaned_blocks().await {
            Ok(()) => {
                return Ok(Response::builder()
                    .body(http_body_util::Either::Left(Full::new(Bytes::from("ok"))))
                    .unwrap());
            }
            Err(e) => {
                error!("Forced GC sweep failed: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(http_body_util::Either::Left(Full::new(Bytes::from("sweep failed"))))
                    .unwrap());
            }
        }
    }

    if req.uri().path().starts_with("/internal/blocks/") {
        let hash_hex = &req.uri().path()["/internal/blocks/".len()..];
        let hash = match hex::decode(hash_hex) {
            Ok(h) if h.len() == 32 => h,
            Ok(_) => return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(http_body_util::Either::Left(Full::new(Bytes::from("Hash must be 32 bytes"))))
                .unwrap()),
            Err(_) => return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(http_body_util::Either::Left(Full::new(Bytes::from("Invalid hash"))))
                .unwrap()),
        };

        return match backend.blocks.get_block(&hash).await {
            Ok(data) => Ok(Response::builder()
                .status(StatusCode::OK)
                .body(http_body_util::Either::Left(Full::new(data)))
                .unwrap()),
            Err(_) => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(http_body_util::Either::Left(Full::new(Bytes::from("Not found"))))
                .unwrap()),
        };
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(http_body_util::Either::Left(Full::new(Bytes::from("Not found"))))
        .unwrap())
}

/// Cap on establishing a peer connection: TCP connect + Noise handshake.
/// Control-plane loops (gossip, fact sync, clock sync) all connect through
/// here; without a bound, a peer that sleeps mid-handshake wedges the loop.
const PEER_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Cap on the request/response phase (HTTP handshake + send + collect body).
const PEER_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Open a noise-encrypted TCP connection to the given peer's internal port.
/// Both the TCP connect and the Noise handshake are bounded so an unreachable
/// or sleeping peer fails fast instead of blocking the caller forever.
async fn noise_connect(
    peer_internal_url: &str,
    private_key: &[u8],
    psk: &[u8; 32],
) -> anyhow::Result<NoiseStream<TcpStream>> {
    use tokio::time::timeout;
    // peer_internal_url is e.g. "http://site-a:8015" — extract host:port
    let url = peer_internal_url.trim_end_matches('/');
    let host_port = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let stream = timeout(PEER_CONNECT_TIMEOUT, TcpStream::connect(host_port))
        .await
        .map_err(|_| anyhow::anyhow!("TCP connect to {host_port} timed out after {PEER_CONNECT_TIMEOUT:?}"))??;
    timeout(PEER_CONNECT_TIMEOUT, NoiseStream::connect(stream, private_key, psk))
        .await
        .map_err(|_| anyhow::anyhow!("Noise handshake with {host_port} timed out after {PEER_CONNECT_TIMEOUT:?}"))?
}

/// Make a JSON GET request over a noise-encrypted connection.
async fn noise_get_json(
    peer_internal_url: &str,
    path: &str,
    secret: &str,
    private_key: &[u8],
    psk: &[u8; 32],
) -> anyhow::Result<(ClusterConfigResponse, Duration)> {
    let noise_stream = noise_connect(peer_internal_url, private_key, psk).await?;
    let io = hyper_util::rt::TokioIo::new(noise_stream);

    let host = peer_internal_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');

    // Bound the whole request/response so a peer that stalls after the handshake
    // cannot hang the clock-sync loop indefinitely.
    tokio::time::timeout(PEER_REQUEST_TIMEOUT, async {
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, http_body_util::Empty<Bytes>>(io).await?;
        tokio::spawn(conn);

        let start = std::time::Instant::now();
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("Host", host)
            .header("X-Shardscape-Secret", secret)
            .body(http_body_util::Empty::<Bytes>::new())?;

        let res = sender.send_request(req).await?;
        let rtt = start.elapsed();

        if !res.status().is_success() {
            anyhow::bail!("Server returned {}", res.status());
        }

        let body = http_body_util::BodyExt::collect(res.into_body()).await?.to_bytes();
        let parsed: ClusterConfigResponse = serde_json::from_slice(&body)?;
        Ok::<_, anyhow::Error>((parsed, rtt))
    })
    .await
    .map_err(|_| anyhow::anyhow!("Clock-sync request to {host} timed out after {PEER_REQUEST_TIMEOUT:?}"))?
}

/// Fetches a peer's own-originated facts after `after`, over Noise. The peer
/// returns up to `FACT_SYNC_BATCH` facts as JSON.
async fn noise_get_facts(
    peer_url: &str,
    after: i64,
    secret: &str,
    private_key: &[u8],
    psk: &[u8; 32],
) -> anyhow::Result<Vec<store::FactRecord>> {
    let noise_stream = noise_connect(peer_url, private_key, psk).await?;
    let io = hyper_util::rt::TokioIo::new(noise_stream);
    let host = peer_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');

    // Bound the whole request/response so a peer that sleeps mid-read cannot
    // wedge the fact-sync loop.
    tokio::time::timeout(PEER_REQUEST_TIMEOUT, async {
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake::<_, http_body_util::Empty<Bytes>>(io).await?;
        tokio::spawn(conn);

        let req = Request::builder()
            .method("GET")
            .uri(format!("/internal/facts/{after}"))
            .header("Host", host)
            .header("X-Shardscape-Secret", secret)
            .body(http_body_util::Empty::<Bytes>::new())?;

        let res = sender.send_request(req).await?;
        if !res.status().is_success() {
            anyhow::bail!("Fact pull returned {}", res.status());
        }
        let body = http_body_util::BodyExt::collect(res.into_body()).await?.to_bytes();
        let facts: Vec<store::FactRecord> = serde_json::from_slice(&body)?;
        Ok::<_, anyhow::Error>(facts)
    })
    .await
    .map_err(|_| anyhow::anyhow!("Fact pull from {host} timed out after {PEER_REQUEST_TIMEOUT:?}"))?
}

/// Pulls and applies new facts from every live peer once. Per-peer failures are
/// logged and skipped — an unreachable peer simply doesn't converge until it
/// returns, which is the whole point of the async fact log.
async fn sync_facts_once(
    db: &db::Db,
    peers: std::collections::HashMap<String, String>,
    secret: &str,
    private_key: &[u8],
    psk: &[u8; 32],
) {
    for (peer_id, peer_url) in peers {
        loop {
            let after = match db.get_cursor(&peer_id).await {
                Ok(c) => c,
                Err(e) => { warn!("Fact sync: cursor read for {peer_id} failed: {e}"); break; }
            };
            let facts = match noise_get_facts(&peer_url, after, secret, private_key, psk).await {
                Ok(f) => { peer_link_ok(&peer_id); f }
                Err(e) => { peer_link_failed(&peer_id, "fact sync", e); break; }
            };
            if facts.is_empty() {
                break;
            }
            let mut max_seq = after;
            let mut applied = 0usize;
            for f in &facts {
                if let Err(e) = db.apply_fact(f).await {
                    warn!("Fact sync: apply (seq {}) from {peer_id} failed: {e}", f.seq);
                    continue;
                }
                max_seq = max_seq.max(f.seq);
                applied += 1;
            }
            if let Err(e) = db.set_cursor(&peer_id, max_seq).await {
                warn!("Fact sync: cursor advance for {peer_id} failed: {e}");
                break;
            }
            tracing::debug!("Fact sync: applied {applied} fact(s) from {peer_id} (cursor → {max_seq})");
            // A short page means we've caught up; a full page means keep draining.
            if (facts.len() as i64) < FACT_SYNC_BATCH {
                break;
            }
        }
    }
}

async fn refresh_clock_offset(
    peer_url: &str,
    config: &config::Config,
    clock: &clock::ClusterClock,
    private_key: &[u8],
    psk: &[u8; 32],
) -> anyhow::Result<()> {
    let (cluster_info, rtt) = noise_get_json(
        peer_url,
        "/internal/cluster/config",
        &config.server.cluster_secret,
        private_key,
        psk,
    ).await?;

    let local_now_micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_micros() as i64;

    let adjusted_leader_time = cluster_info.cluster_time_micros + (rtt.as_micros() / 2) as i64;
    let offset_micros = adjusted_leader_time - local_now_micros;
    let offset_ms = offset_micros / 1000;

    let old_offset = clock.get_offset();
    if (offset_ms - old_offset).abs() > 10 {
        info!("Updating clock offset: {}ms -> {}ms (drift detected)", old_offset, offset_ms);
        clock.set_offset(offset_ms);
    }

    Ok(())
}

/// Performs the join handshake against `peer_url` (a peer's internal address):
/// computes the initial clock offset, registers this node at the peer, and
/// returns the peer's `(location_id, url)` so the caller can record it once the
/// store is open. Backfill of existing data is then automatic — the fact-sync
/// task starts every peer at cursor 0 and pulls the whole corpus on its first
/// cycle; membership gossip discovers the rest of the mesh.
async fn perform_join_handshake(
    peer_url: &str,
    config: &mut config::Config,
    clock: &clock::ClusterClock,
    config_path: &str,
    private_key: &[u8],
    psk: &[u8; 32],
) -> anyhow::Result<(String, String)> {
    let (cluster_info, rtt) = noise_get_json(
        peer_url,
        "/internal/cluster/config",
        &config.server.cluster_secret,
        private_key,
        psk,
    ).await?;

    let local_now_micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_micros() as i64;
    let adjusted_leader_time = cluster_info.cluster_time_micros + (rtt.as_micros() / 2) as i64;
    let offset_micros = adjusted_leader_time - local_now_micros;
    let offset_ms = offset_micros / 1000;

    info!("Clock offset calculated: {}ms (RTT: {:?})", offset_ms, rtt);
    clock.set_offset(offset_ms);

    // Register ourselves at the peer so it can pull our facts too (bidirectional).
    let register_path = format!(
        "/internal/join?id={}&addr={}",
        config.storage.local_location_id, config.server.advertise_addr
    );
    if let Err(e) = noise_get_bytes(peer_url, &register_path, &config.server.cluster_secret, private_key, psk).await {
        warn!("Could not register self at peer (will still sync once peer learns us): {e}");
    }

    let mut new_config = config.clone();
    new_config.server.clock_offset_ms = offset_ms;
    new_config.save(config_path)?;
    *config = new_config;

    // Prefer the peer's self-reported id; fall back to the URL we dialled.
    let peer_id = if cluster_info.location_id.is_empty() {
        peer_url.to_string()
    } else {
        cluster_info.location_id
    };
    Ok((peer_id, peer_url.to_string()))
}

/// Minimal GET over Noise returning the raw response body. Used for membership
/// endpoints (/internal/join, /internal/nodes).
async fn noise_get_bytes(
    peer_url: &str,
    path: &str,
    secret: &str,
    private_key: &[u8],
    psk: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    let noise_stream = noise_connect(peer_url, private_key, psk).await?;
    let io = hyper_util::rt::TokioIo::new(noise_stream);
    let host = peer_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');

    // Bound the whole request/response so a peer that sleeps mid-read cannot
    // wedge the membership-gossip loop.
    tokio::time::timeout(PEER_REQUEST_TIMEOUT, async {
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake::<_, http_body_util::Empty<Bytes>>(io).await?;
        tokio::spawn(conn);
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("Host", host)
            .header("X-Shardscape-Secret", secret)
            .body(http_body_util::Empty::<Bytes>::new())?;
        let res = sender.send_request(req).await?;
        if !res.status().is_success() {
            anyhow::bail!("Peer returned {}", res.status());
        }
        Ok::<_, anyhow::Error>(http_body_util::BodyExt::collect(res.into_body()).await?.to_bytes().to_vec())
    })
    .await
    .map_err(|_| anyhow::anyhow!("Request to {host} timed out after {PEER_REQUEST_TIMEOUT:?}"))?
}

/// Per-peer link state for edge-triggered logging: periodic loops (membership
/// gossip, fact sync, clock sync) log once when a peer becomes unreachable and
/// once when it recovers, instead of on every heartbeat. Repeats are debug-level.
static PEER_LINK_UP: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, bool>>> =
    std::sync::LazyLock::new(Default::default);

fn peer_link_failed(peer_id: &str, context: &str, err: impl std::fmt::Display) {
    let was_up = PEER_LINK_UP.lock().unwrap().insert(peer_id.to_string(), false);
    if was_up != Some(false) {
        warn!("Peer {peer_id} unreachable ({context}): {err} — suppressing repeats until it recovers");
    } else {
        tracing::debug!("Peer {peer_id} still unreachable ({context}): {err}");
    }
}

fn peer_link_ok(peer_id: &str) {
    let was_up = PEER_LINK_UP.lock().unwrap().insert(peer_id.to_string(), true);
    if was_up == Some(false) {
        info!("Peer {peer_id} reachable again");
    }
}

/// Pulls each peer's membership view and records any new nodes, converging the
/// mesh (a leaf learns sibling leaves through the node it joined).
async fn gossip_membership(
    db: &db::Db,
    peers: &std::collections::HashMap<String, String>,
    secret: &str,
    private_key: &[u8],
    psk: &[u8; 32],
) {
    for (peer_id, peer_url) in peers {
        match noise_get_bytes(peer_url, "/internal/nodes", secret, private_key, psk).await {
            Ok(body) => {
                peer_link_ok(peer_id);
                if let Ok(nodes) = serde_json::from_slice::<Vec<(String, String)>>(&body) {
                    for (id, url) in nodes {
                        if let Err(e) = db.record_peer(&id, &url).await {
                            warn!("Membership: failed to record {id}: {e}");
                        }
                    }
                }
            }
            Err(e) => peer_link_failed(peer_id, "membership gossip", e),
        }
    }
}

/// Parses `k=v&k=v` query pairs with percent-decoding.
fn url_query_pairs(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            Some((percent_decode(k), percent_decode(v)))
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn render_k8s_uses_site_and_ports_from_config() {
        let mut config = config::Config::default();
        config.storage.local_location_id = "office".to_string();
        config.server.s3_bind_addr = "0.0.0.0:9000".to_string();
        config.server.internal_bind_addr = "0.0.0.0:9001".to_string();
        let y = render_k8s_manifests(&config);
        assert!(y.contains("shardscape-office"));
        assert!(y.contains("name: shardscape")); // namespace
        assert!(y.contains("containerPort: 9000"));
        assert!(y.contains("containerPort: 9001"));
        assert!(y.contains(r#"args: ["serve", "--config", "/data/config.toml"]"#));
    }

    #[test]
    fn random_hex_is_right_length_and_varies() {
        let a = random_hex(32);
        let b = random_hex(32);
        assert_eq!(a.len(), 64); // 32 bytes → 64 hex chars
        assert_ne!(a, b, "two draws should differ");
    }
}

async fn bootstrap_admin_user(db: &db::Db) -> anyhow::Result<()> {
    if db.get_user("admin").await?.is_none() {
        let password = std::env::var("SS_ADMIN_PASSWORD")
            .map_err(|_| anyhow::anyhow!("SS_ADMIN_PASSWORD env var must be set for initial bootstrap"))?;
        info!("Bootstrapping admin user...");
        db.create_user("admin", &password, &admin_policy()).await?;
    }
    Ok(())
}

fn admin_policy() -> db::Policy {
    db::Policy {
        statements: vec![db::PolicyStatement {
            effect: "Allow".to_string(),
            actions: vec!["*".to_string()],
            resources: vec!["*".to_string()],
        }],
    }
}

/// Cryptographically-random hex string of `n_bytes` bytes.
fn random_hex(n_bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; n_bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// `shardscape init` — generate secrets + config and bootstrap the admin user.
/// The first site in a cluster. Nothing to hand-edit.
async fn run_init(args: InitArgs) -> anyhow::Result<()> {
    if std::path::Path::new(&args.config).exists() {
        anyhow::bail!(
            "Config '{}' already exists — refusing to overwrite. Delete it to re-init.",
            args.config
        );
    }
    let cluster_secret = args.cluster_secret.clone().unwrap_or_else(|| random_hex(32));
    let admin_password = random_hex(24);

    let config = build_site_config(&args.site, cluster_secret.clone())?;
    config.save(&args.config)?;

    // Bootstrap the admin user directly into the new store so `serve` needs no
    // SS_ADMIN_PASSWORD. Joining sites receive admin via fact-log replication.
    let clock = Arc::new(clock::ClusterClock::new(0));
    let db = db::Db::new(&config.database.db_path, args.site.location_id.clone(), clock).await?;
    db.create_user("admin", &admin_password, &admin_policy()).await?;

    println!("\n  Shardscape site '{}' initialised.\n", args.site.location_id);
    println!("  config:           {}", args.config);
    println!("  data dir:         {}", args.site.data_dir);
    println!("  S3 endpoint:      http://{}", config.server.s3_bind_addr);
    println!();
    println!("  Admin access key: admin");
    println!("  Admin secret key: {admin_password}");
    println!("  Cluster secret:   {cluster_secret}");
    println!();
    println!("  Start this node:  shardscape serve --config {}", args.config);
    println!("  Add another site: shardscape join {} --secret {}", config.server.advertise_addr, cluster_secret);
    println!();
    Ok(())
}

/// `shardscape status` — local cluster, replication, and GC health.
async fn run_status(config_path: String) -> anyhow::Result<()> {
    let config = config::Config::load(&config_path)?;
    let clock = Arc::new(clock::ClusterClock::new(config.server.clock_offset_ms));
    let db = db::Db::new(
        &config.database.db_path,
        config.storage.local_location_id.clone(),
        clock,
    )
    .await?;
    let stats = db.stats().await?;
    let peers = db.get_peers().await?;

    println!("Shardscape site '{}'", config.storage.local_location_id);
    println!("  S3 endpoint:        http://{}", config.server.s3_bind_addr);
    println!("  live objects:       {}", stats.live_objects);
    println!("  local blocks:       {} ({})", stats.local_blocks, disk::format_bytes(stats.local_block_bytes as u64));
    println!("  blocks to pull:     {}", stats.pending_pulls);
    println!("  pending GC:         {}", stats.pending_deletions);
    println!("  fact-log length:    {}", stats.fact_count);
    let guard = disk::DiskGuard::from_config(&config);
    guard.set_local_usage(stats.local_block_bytes as u64);
    let guard_state = match guard.check() {
        None if !guard.enabled() => "off".to_string(),
        None => {
            let mut parts = Vec::new();
            if guard.free_space_enabled() {
                parts.push(format!("reserve {}", disk::format_bytes(guard.min_free_bytes())));
            }
            if guard.quota_enabled() {
                parts.push(format!("cap {}", disk::format_bytes(guard.max_bytes())));
            }
            format!("OK, {}", parts.join(", "))
        }
        Some(disk::GuardTrip::LowFreeSpace) => {
            format!("TRIPPED — writes refused (reserve {})", disk::format_bytes(guard.min_free_bytes()))
        }
        Some(disk::GuardTrip::OverQuota) => {
            format!("TRIPPED — writes refused (cap {})", disk::format_bytes(guard.max_bytes()))
        }
    };
    if guard.free_space_enabled() {
        println!("  disk free:          {} (guard: {})", disk::format_bytes(guard.free_bytes()), guard_state);
    } else {
        println!("  disk guard:         {}", guard_state);
    }
    println!("  peers:              {}", peers.len());
    for (id, url) in peers {
        let cursor = db.get_cursor(&id).await.unwrap_or(0);
        println!("    - {id:<14} {url}  (synced through fact #{cursor})");
    }
    Ok(())
}

/// `shardscape render-k8s` — emit a self-contained single-node manifest set.
/// Manifests are an output of config, never a hand-edited input.
async fn run_render_k8s(config_path: String, out: Option<String>) -> anyhow::Result<()> {
    let config = config::Config::load(&config_path)?;
    let manifests = render_k8s_manifests(&config);
    match out {
        Some(dir) => {
            std::fs::create_dir_all(&dir)?;
            let path = std::path::Path::new(&dir).join("shardscape.yaml");
            std::fs::write(&path, manifests)?;
            println!("Wrote {}", path.display());
        }
        None => print!("{manifests}"),
    }
    Ok(())
}

fn render_k8s_manifests(config: &config::Config) -> String {
    let site = &config.storage.local_location_id;
    let s3_port = config.server.s3_bind_addr.rsplit(':').next().unwrap_or("8014");
    let internal_port = config.server.internal_bind_addr.rsplit(':').next().unwrap_or("8015");
    // The cluster secret is the only sensitive value; everything else is plain
    // config. We reference it from a Secret the operator creates out-of-band so
    // it never lands in a committed manifest.
    format!(
        r#"# Rendered by `shardscape render-k8s` for site '{site}'. Do not hand-edit;
# re-render from config.toml instead.
apiVersion: v1
kind: Namespace
metadata:
  name: shardscape
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: shardscape-data-{site}
  namespace: shardscape
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 50Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: shardscape-{site}
  namespace: shardscape
spec:
  replicas: 1
  selector:
    matchLabels: {{ app: shardscape, site: {site} }}
  template:
    metadata:
      labels: {{ app: shardscape, site: {site} }}
    spec:
      initContainers:
        # Idempotently initialise this site on first boot. The generated admin +
        # cluster secrets appear in this container's logs; capture them to add
        # more sites (`shardscape join`). Re-runs are a no-op once config exists.
        - name: init
          image: shardscape:latest
          command: ["/bin/sh", "-c"]
          args:
            - >-
              test -f /data/config.toml ||
              /usr/local/bin/shardscape init --config /data/config.toml --data-dir /data
              --location-id {site} --s3-addr 0.0.0.0:{s3_port}
              --internal-addr 0.0.0.0:{internal_port}
              --advertise http://shardscape-{site}.shardscape.svc.cluster.local:{internal_port}
          volumeMounts:
            - {{ name: data, mountPath: /data }}
      containers:
        - name: shardscape
          image: shardscape:latest
          args: ["serve", "--config", "/data/config.toml"]
          ports:
            - {{ containerPort: {s3_port}, name: s3 }}
            - {{ containerPort: {internal_port}, name: internal }}
          volumeMounts:
            - {{ name: data, mountPath: /data }}
          readinessProbe:
            tcpSocket: {{ port: s3 }}
            initialDelaySeconds: 2
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: shardscape-data-{site}
---
apiVersion: v1
kind: Service
metadata:
  name: shardscape-{site}
  namespace: shardscape
spec:
  selector: {{ app: shardscape, site: {site} }}
  ports:
    - {{ name: s3, port: {s3_port}, targetPort: s3 }}
    - {{ name: internal, port: {internal_port}, targetPort: internal }}
"#
    )
}
