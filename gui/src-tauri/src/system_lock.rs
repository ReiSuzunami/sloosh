#[cfg(target_os = "macos")]
pub fn install(controller: crate::Controller) {
    use block2::RcBlock;
    use objc2_app_kit::{
        NSWorkspace, NSWorkspaceScreensDidSleepNotification,
        NSWorkspaceSessionDidResignActiveNotification, NSWorkspaceWillSleepNotification,
    };
    use objc2_foundation::NSNotification;
    use std::ptr::NonNull;

    let center = NSWorkspace::sharedWorkspace().notificationCenter();
    // SAFETY: AppKit exports these as process-lifetime notification-name
    // constants on supported macOS versions.
    let notification_names = unsafe {
        [
            NSWorkspaceWillSleepNotification,
            NSWorkspaceScreensDidSleepNotification,
            NSWorkspaceSessionDidResignActiveNotification,
        ]
    };
    for name in notification_names {
        let controller = controller.clone();
        let block = RcBlock::new(move |_notification: NonNull<NSNotification>| {
            controller.lock();
        });
        // SAFETY: The block has the exact notification callback signature,
        // captures only thread-safe Rust state, and the workspace notification
        // center retains the observer for the lifetime of this app process.
        unsafe {
            center.addObserverForName_object_queue_usingBlock(Some(name), None, None, &block)
        };
    }
}

#[cfg(not(target_os = "macos"))]
pub fn install(_controller: crate::Controller) {}
