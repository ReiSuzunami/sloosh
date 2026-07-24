#[cfg(any(target_os = "macos", test))]
const LIGHT_ICON_PNG: &[u8] = include_bytes!("../../public/icon-light.png");
#[cfg(any(target_os = "macos", test))]
const DARK_ICON_PNG: &[u8] = include_bytes!("../../public/icon-dark.png");

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DockIconVariant {
    Light,
    Dark,
}

#[cfg(any(target_os = "macos", test))]
impl DockIconVariant {
    fn for_theme(theme: tauri::Theme) -> Self {
        match theme {
            tauri::Theme::Dark => Self::Dark,
            tauri::Theme::Light => Self::Light,
            _ => Self::Light,
        }
    }

    fn png(self) -> &'static [u8] {
        match self {
            Self::Light => LIGHT_ICON_PNG,
            Self::Dark => DARK_ICON_PNG,
        }
    }
}

#[cfg(target_os = "macos")]
pub fn handle_run_event(app_handle: &tauri::AppHandle, event: &tauri::RunEvent) {
    use tauri::Manager as _;

    let theme = match event {
        tauri::RunEvent::Ready => app_handle
            .get_webview_window("main")
            .and_then(|window| window.theme().ok()),
        tauri::RunEvent::WindowEvent {
            event: tauri::WindowEvent::ThemeChanged(theme),
            ..
        } => Some(*theme),
        _ => None,
    };

    if let Some(theme) = theme
        && let Err(error) = apply_variant(DockIconVariant::for_theme(theme))
    {
        eprintln!("warning: could not update the macOS Dock icon: {error}");
    }
}

#[cfg(target_os = "macos")]
fn apply_variant(variant: DockIconVariant) -> Result<(), String> {
    use objc2::{AllocAnyThread as _, MainThreadMarker};
    use objc2_app_kit::{NSApplication, NSImage};
    use objc2_foundation::NSData;

    let main_thread = MainThreadMarker::new()
        .ok_or_else(|| "AppKit icon updates must run on the main thread".to_string())?;
    let data = NSData::with_bytes(variant.png());
    let image = NSImage::initWithData(NSImage::alloc(), &data)
        .ok_or_else(|| "the embedded PNG could not be decoded by AppKit".to_string())?;
    let application = NSApplication::sharedApplication(main_thread);
    // SAFETY: `MainThreadMarker` proves this runs on AppKit's main thread,
    // and a decoded, non-null NSImage is valid for the strong icon property.
    unsafe {
        application.setApplicationIconImage(Some(&image));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn handle_run_event(_app_handle: &tauri::AppHandle, _event: &tauri::RunEvent) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dock_icon_variant_follows_system_theme() {
        assert_eq!(
            DockIconVariant::for_theme(tauri::Theme::Light),
            DockIconVariant::Light
        );
        assert_eq!(
            DockIconVariant::for_theme(tauri::Theme::Dark),
            DockIconVariant::Dark
        );
    }

    #[test]
    fn dock_icon_variants_are_distinct_png_assets() {
        const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

        assert!(DockIconVariant::Light.png().starts_with(PNG_SIGNATURE));
        assert!(DockIconVariant::Dark.png().starts_with(PNG_SIGNATURE));
        assert_ne!(DockIconVariant::Light.png(), DockIconVariant::Dark.png());
    }
}
