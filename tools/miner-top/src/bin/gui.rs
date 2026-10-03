//! coincync miner-gui — a native desktop app (WebView2 window) showing the
//! polished dashboard. Opens as its own window: no browser to launch, no URL to
//! type. It starts the local `/data` bridge (real rig `/metrics` + node
//! `get_info`) in a background thread, then points a webview at it.
//!
//!   miner-gui --rig http://127.0.0.1:9109/metrics --node http://127.0.0.1:28081 \
//!             [--address <payout>] [--reward <cync>] [--port 9110] [--interval 3]

use std::time::Duration;

use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};
use wry::WebViewBuilder;

fn main() -> wry::Result<()> {
    let mut rig = None;
    let mut node = None;
    let mut address = String::new();
    let mut reward = 0.0_f64;
    let mut interval = 3_u64;
    let mut port = 9110_u16;
    // Maintainer colony view (optional). `--tick` points at the coincync-tick
    // sidecar's metrics origin; `--tick-token` (or COINCYNC_TICK_MAINTAINER_TOKEN)
    // is the maintainer Bearer token that unlocks its `/colony` endpoint.
    let mut tick: Option<String> = None;
    let mut tick_token =
        std::env::var("COINCYNC_TICK_MAINTAINER_TOKEN").unwrap_or_default();
    let mut it = std::env::args().skip(1);
    while let Some(f) = it.next() {
        match f.as_str() {
            "--rig" => rig = it.next(),
            "--node" => node = it.next(),
            "--address" => address = it.next().unwrap_or_default(),
            "--reward" => reward = it.next().and_then(|v| v.parse().ok()).unwrap_or(0.0),
            "--interval" => interval = it.next().and_then(|v| v.parse().ok()).unwrap_or(3),
            "--port" => port = it.next().and_then(|v| v.parse().ok()).unwrap_or(9110),
            "--tick" => tick = it.next(),
            "--tick-token" => tick_token = it.next().unwrap_or_default(),
            _ => {}
        }
    }
    let (rig, node) = match (rig, node) {
        (Some(r), Some(n)) => (r, n),
        _ => {
            eprintln!("usage: miner-gui --rig <metrics-url> --node <rpc-url> [--address <payout>] [--reward <cync>] [--port 9110] [--interval 3]");
            std::process::exit(2);
        }
    };

    // Serve the dashboard + live /data locally, in the background.
    {
        let (rig, node, address) = (rig.clone(), node.clone(), address.clone());
        std::thread::spawn(move || {
            let _ = coincync_miner_top::serve::serve(
                port, rig, node, address, reward, interval, tick, tick_token,
            );
        });
    }
    // Give the listener a moment to bind before the webview loads it.
    std::thread::sleep(Duration::from_millis(400));

    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("coincync miner")
        .with_inner_size(LogicalSize::new(1240.0, 800.0))
        .with_min_inner_size(LogicalSize::new(820.0, 560.0))
        .build(&event_loop)
        .expect("create window");

    let _webview = WebViewBuilder::new(&window)
        .with_url(format!("http://127.0.0.1:{port}"))
        .with_background_color((10, 11, 12, 255))
        .build()?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            *control_flow = ControlFlow::Exit;
            std::process::exit(0);
        }
    });
}
