#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    use std::{
        env,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use leptos::prelude::get_configuration;
    use secopy::{api::AppState, server::build_router_with_state};

    tracing_subscriber::fmt::init();

    let conf = get_configuration(Some("Cargo.toml"))
        .or_else(|error| {
            tracing::warn!(
            ?error,
            "failed to load Cargo.toml-based Leptos configuration; falling back to env/defaults"
        );
            get_configuration(None)
        })
        .expect("failed to load Leptos configuration");
    let mut leptos_options = conf.leptos_options;
    let addr = env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
        .unwrap_or(leptos_options.site_addr);
    leptos_options.site_addr = addr;
    let room_ttl = env::var("SCPY_ROOM_TTL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(60 * 60 * 24));
    let redis_url = env::var("SCPY_REDIS_URL")
        .ok()
        .or_else(|| env::var("REDIS_URL").ok());
    let reclaim_interval = env::var("SCPY_RECLAIM_INTERVAL_MILLIS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_secs(1));
    let reclaim_batch_limit = env::var("SCPY_RECLAIM_BATCH_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(128);
    let app_state = if let Some(redis_url) = redis_url {
        tracing::info!("starting with redis room store");
        AppState::redis_with_reclaimer(&redis_url, room_ttl, reclaim_interval, reclaim_batch_limit)
            .await
            .expect("failed to connect to redis room store")
    } else {
        tracing::info!("starting with in-memory room store");
        AppState::memory(room_ttl)
    };
    let app = build_router_with_state(leptos_options.clone(), app_state);

    tracing::info!(%addr, "starting secopy");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind TCP listener");

    axum::serve(listener, app.into_make_service())
        .await
        .expect("axum server error");
}

#[cfg(not(feature = "ssr"))]
pub fn main() {}
