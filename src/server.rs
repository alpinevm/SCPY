use axum::{extract::FromRef, Router};
use leptos::config::LeptosOptions;
use leptos_axum::{generate_route_list, LeptosRoutes};
use tower_http::{compression::CompressionLayer, services::ServeFile, trace::TraceLayer};

use crate::{
    api::{api_router, AppState},
    app::{shell, App},
};

#[derive(Clone)]
pub struct ServerState {
    api: AppState,
    leptos_options: LeptosOptions,
}

impl FromRef<ServerState> for AppState {
    fn from_ref(input: &ServerState) -> Self {
        input.api.clone()
    }
}

impl FromRef<ServerState> for LeptosOptions {
    fn from_ref(input: &ServerState) -> Self {
        input.leptos_options.clone()
    }
}

pub fn build_router(leptos_options: LeptosOptions) -> Router {
    build_router_with_state(leptos_options, AppState::default())
}

pub fn build_router_with_state(leptos_options: LeptosOptions, api_state: AppState) -> Router {
    let routes = generate_route_list(App);
    let wasm_alias_path = format!(
        "/{}/{}_bg.wasm",
        leptos_options.site_pkg_dir, leptos_options.output_name
    );
    let wasm_asset_path = format!(
        "{}/{}/{}.wasm",
        leptos_options.site_root, leptos_options.site_pkg_dir, leptos_options.output_name
    );
    let state = ServerState {
        api: api_state,
        leptos_options: leptos_options.clone(),
    };

    api_router::<ServerState>()
        .route_service(&wasm_alias_path, ServeFile::new(wasm_asset_path))
        .leptos_routes(&state, routes, {
            let leptos_options = leptos_options.clone();
            move || shell(leptos_options.clone())
        })
        .fallback(leptos_axum::file_and_error_handler::<ServerState, _>(shell))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
