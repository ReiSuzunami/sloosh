//! Remote-forward route state and byte-pump mechanics.
//!
//! This module depends only on a stable lease grant. It deliberately does
//! not depend on `daemon::forward`; that owner constructs these values and
//! hands them across the SSH boundary.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::daemon::lease;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ForwardRouteState {
    Pending,
    Active,
    Closed,
}

#[derive(Clone)]
pub(crate) struct ForwardRouteLifecycle {
    state: watch::Sender<ForwardRouteState>,
}

impl ForwardRouteLifecycle {
    pub(crate) fn new() -> Self {
        let (state, _receiver) = watch::channel(ForwardRouteState::Pending);
        Self { state }
    }

    pub(crate) fn state(&self) -> ForwardRouteState {
        *self.state.borrow()
    }

    pub(crate) fn is_active(&self) -> bool {
        self.state() == ForwardRouteState::Active
    }

    pub(crate) fn activate(&self) -> bool {
        self.state.send_if_modified(|state| {
            if *state == ForwardRouteState::Pending {
                *state = ForwardRouteState::Active;
                true
            } else {
                false
            }
        })
    }

    pub(crate) fn close(&self) -> bool {
        self.state.send_if_modified(|state| {
            if *state == ForwardRouteState::Closed {
                false
            } else {
                *state = ForwardRouteState::Closed;
                true
            }
        })
    }

    pub(crate) async fn wait_closed(&self) {
        let mut receiver = self.state.subscribe();
        loop {
            let state = *receiver.borrow_and_update();
            if state == ForwardRouteState::Closed {
                return;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

/// Data needed to service a server-initiated `forwarded-tcpip` channel.
#[derive(Clone)]
pub(crate) struct ForwardRoute {
    pub(crate) local_host: String,
    pub(crate) local_port: u16,
    pub(crate) grant: lease::LeaseGrant,
    pub(crate) tunnel_count: Arc<AtomicUsize>,
    pub(crate) lifecycle: ForwardRouteLifecycle,
}

#[derive(Debug)]
pub(super) enum ForwardTargetConnectError {
    Closed,
    TimedOut,
    Io(std::io::Error),
}

pub(super) async fn race_forward_target_connect<T, F>(
    lifecycle: &ForwardRouteLifecycle,
    timeout: Duration,
    connect: F,
) -> Result<T, ForwardTargetConnectError>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    tokio::select! {
        biased;
        _ = lifecycle.wait_closed() => Err(ForwardTargetConnectError::Closed),
        result = tokio::time::timeout(timeout, connect) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(ForwardTargetConnectError::Io(error)),
            Err(_) => Err(ForwardTargetConnectError::TimedOut),
        },
    }
}

pub(super) async fn pump_forwarded_tcpip(
    channel: russh::Channel<russh::client::Msg>,
    mut tcp: TcpStream,
    route: ForwardRoute,
) {
    route.tunnel_count.fetch_add(1, Ordering::SeqCst);
    let mut remote = channel.into_stream();
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut tcp, &mut remote) => {}
        _ = route.lifecycle.wait_closed() => {}
    }
    route.tunnel_count.fetch_sub(1, Ordering::SeqCst);
}
