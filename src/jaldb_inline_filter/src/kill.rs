use log::{info, warn};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::broadcast;

/// Broadcast channel to receive shutdown signal
pub type KillChannel = broadcast::Receiver<()>;

/// Add signal hooks and return a broadcast channel to distribute them
pub fn setup_signals() -> anyhow::Result<broadcast::Sender<()>> {
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigpipe = signal(SignalKind::pipe())?;
    let mut sigabrt = signal(SignalKind::from_raw(libc::SIGABRT))?;

    let (kill, _) = broadcast::channel(1);
    tokio::spawn({
        let kill = kill.clone();
        async move {
            tokio::select! {
                _ = sigint.recv() => info!("sigint received..."),
                _ = sigterm.recv() => info!("sigterm received..."),
                _ = sigpipe.recv() => info!("sigpipe received..."),
                _ = sigabrt.recv() => info!("sigabrt received..."),
            }
            if let Err(e) = kill.send(()) {
                warn!("kill signal tx failed: {e:?}");
            }
        }
    });
    Ok(kill)
}
