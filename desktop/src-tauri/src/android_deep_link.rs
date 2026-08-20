//! Narrow Android callback routing, kept outside the Android-only module so it can be tested on
//! every native CI platform.

use url::Url;

/// Converts only static, non-secret Android callback routes into a frontend notice. Query
/// parameters, fragments, credential values, and arbitrary URLs are not forwarded across the
/// native/WebView boundary.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn safe_android_deep_link(url: &Url) -> Option<&'static str> {
    if url.username() != "" || url.password().is_some() || url.port().is_some() {
        return None;
    }
    let custom = url.scheme() == "hasilan-pass"
        && url.host_str() == Some("account")
        && url.query().is_none()
        && url.fragment().is_none();
    match (custom, url.path()) {
        (true, "/open") => Some("open"),
        (true, "/verify-email") => Some("verify-email"),
        (true, "/invitation") => Some("invitation"),
        (true, "/passkey") => Some("passkey"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::safe_android_deep_link;
    use url::Url;

    fn parse_url(value: &str) -> Url {
        match Url::parse(value) {
            Ok(url) => url,
            Err(error) => panic!("test URL must parse: {error}"),
        }
    }

    #[test]
    fn android_deep_links_allow_only_static_account_callbacks() {
        for (url, action) in [
            ("hasilan-pass://account/open", "open"),
            ("hasilan-pass://account/verify-email", "verify-email"),
            ("hasilan-pass://account/invitation", "invitation"),
            ("hasilan-pass://account/passkey", "passkey"),
        ] {
            assert_eq!(safe_android_deep_link(&parse_url(url)), Some(action));
        }
    }

    #[test]
    fn android_deep_links_reject_data_and_untrusted_routes() {
        for url in [
            "hasilan-pass://account/open?token=secret",
            "hasilan-pass://account/open#token",
            "hasilan-pass://account:8443/open",
            "hasilan-pass://other/open",
            "hasilan-pass://account/reset-password",
            "https://account/open",
            "hasilan-pass://user@account/open",
        ] {
            assert_eq!(safe_android_deep_link(&parse_url(url)), None, "{url}");
        }
    }
}
