//! Invite page
pub const HTML: &str = include_str!("../assets/invite.html");
pub const LOGO: &[u8] = include_bytes!("../assets/app-logo.png");

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invitation_assets_are_bundled_without_a_service_source_dependency() {
        assert!(HTML.contains("Join project"));
        assert!(HTML.contains("miliastra-collab:"));
        assert!(HTML.contains("https://miliastra.dev"));
        assert!(LOGO.starts_with(b"\x89PNG\r\n\x1a\n"));
    }
}
