pub(crate) fn unexpected_daemon_response(action: &str) -> String {
    format!(
        "The local daemon returned an unexpected response while {action}. Restart Sloosh and try \
         again. [GUI_DAEMON_PROTOCOL]"
    )
}

pub(crate) fn daemon_request_failed(action: &str) -> String {
    format!(
        "Sloosh could not reach the trusted local daemon while {action}. Check `sloosh daemon \
         status`, then try again. [GUI_DAEMON_UNAVAILABLE]"
    )
}

pub(crate) fn pin_status_failed() -> String {
    "Sloosh could not read approval PIN state. Review local setup and try again. \
     [GUI_PIN_STATUS]"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_gui_errors_never_embed_raw_backend_details() {
        let unexpected = unexpected_daemon_response("loading hosts");
        let transport = daemon_request_failed("loading hosts");

        for message in [unexpected, transport] {
            assert!(message.contains("loading hosts"));
            assert!(message.contains("[GUI_"));
            assert!(!message.contains("/Users/private"));
            assert!(!message.contains("SecretString"));
        }
    }
}
