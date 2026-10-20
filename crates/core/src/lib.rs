pub mod control;
pub mod coordination;
pub mod decisions;
pub mod invitation_page;
pub mod model;
pub mod opaque;
pub mod presence;
pub mod presence_board;
pub use model::*;
pub fn hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

pub mod constants;
pub mod errors;

/// Strip comments and empty lines
pub fn contract_source(source: &str) -> String {
    source
        .lines()
        .map(str::trim_end)
        .filter(|line| {
            let line = line.trim_start();
            !line.is_empty() && !line.starts_with("//")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Creates hash of contract-related files (need to be the same on client & server)
pub fn contract_fingerprint() -> &'static str {
    static VALUE: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        let source = concat!(
            include_str!("control.rs"),
            include_str!("coordination.rs"),
            include_str!("constants.rs"),
            include_str!("errors.rs"),
            include_str!("model.rs"),
            include_str!("opaque.rs"),
            include_str!("presence.rs")
        );
        hash(contract_source(source).as_bytes())
    });
    VALUE.as_str()
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    #[test]
    fn comments_blank_lines_and_line_endings_do_not_change_the_contract() {
        let code = "pub struct A {\n    pub b: u8,\n}\n";
        let commented = "//! Module docs.\r\n/// A thing.\r\npub struct A {\r\n\r\n    // why b\r\n    pub b: u8,   \r\n}\r\n";
        assert_eq!(contract_source(code), contract_source(commented));
        let changed = "pub struct A {\n    pub b: u16,\n}\n";
        assert_ne!(contract_source(code), contract_source(changed));
    }
    #[test]
    fn matches_the_fingerprint_pinned_by_check_contract_py() {
        let pinned: serde_json::Value =
            serde_json::from_str(include_str!("../../../contract.json")).unwrap();
        assert_eq!(pinned["fingerprint"], contract_fingerprint());
    }
}
