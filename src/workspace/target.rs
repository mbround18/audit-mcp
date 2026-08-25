//! Parsing and validating what a caller asked us to scan.
//!
//! Parsing is total and side-effect free — it never touches the network — so
//! the whole surface is exhaustively unit-testable. Address validation is
//! separated from address *classification* for the same reason: the rules
//! about which addresses are off limits can be tested without DNS.

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};

/// How a remote repository is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteScheme {
    Https,
    Ssh,
}

impl RemoteScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Https => "git_https",
            Self::Ssh => "git_ssh",
        }
    }
}

/// A repository to clone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteTarget {
    pub scheme: RemoteScheme,
    pub host: String,
    /// `owner/repo`, without a trailing `.git`.
    pub path: String,
    /// The URL handed to `git`. Never contains credentials.
    pub url: String,
    /// Branch, tag, or commit, when the caller asked for one.
    pub reference: Option<String>,
}

/// What the `target` argument turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetExpression {
    LocalPath(PathBuf),
    Remote(RemoteTarget),
}

impl TargetExpression {
    pub fn is_remote(&self) -> bool {
        matches!(self, Self::Remote(_))
    }
}

/// Parse a target expression. Never performs I/O beyond checking whether a
/// path exists, which is what makes "an existing local path always wins"
/// decidable.
///
/// An optional ref may be appended as `…#branch`, `…#v1.2.3`, or `…#<sha>`.
pub fn parse(target: &str) -> Result<TargetExpression, String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err("target must not be empty".to_string());
    }

    // An existing local path always wins, so no caller's target can change
    // meaning by us learning to understand URLs.
    if Path::new(trimmed).exists() {
        return Ok(TargetExpression::LocalPath(PathBuf::from(trimmed)));
    }

    let (base, reference) = split_reference(trimmed);

    if let Some(remote) = parse_https(base, reference.clone())? {
        return Ok(TargetExpression::Remote(remote));
    }
    if let Some(remote) = parse_ssh(base, reference.clone())? {
        return Ok(TargetExpression::Remote(remote));
    }
    if let Some(remote) = parse_shorthand(base, reference) {
        return Ok(TargetExpression::Remote(remote));
    }

    // Anything path-shaped that does not exist is a local path that will fail
    // to resolve, which is a clearer error than a misparsed URL.
    if base.starts_with('/') || base.starts_with('.') || base.starts_with('~') {
        return Ok(TargetExpression::LocalPath(PathBuf::from(base)));
    }

    Err(format!(
        "target '{target}' is neither an existing path nor a recognized repository. Expected an absolute path, an https:// or ssh:// git URL, or owner/repo."
    ))
}

/// Split a trailing `#ref`, being careful not to mistake a fragment inside a
/// path for one.
fn split_reference(target: &str) -> (&str, Option<String>) {
    match target.rsplit_once('#') {
        Some((base, reference)) if !reference.is_empty() && !base.is_empty() => {
            (base, Some(reference.to_string()))
        }
        _ => (target, None),
    }
}

fn parse_https(base: &str, reference: Option<String>) -> Result<Option<RemoteTarget>, String> {
    for prefix in ["https://", "http://"] {
        if let Some(rest) = base.strip_prefix(prefix) {
            if prefix == "http://" {
                return Err(
                    "refusing to clone over plaintext http; use https:// or ssh://".to_string(),
                );
            }
            let (authority, path) = rest
                .split_once('/')
                .ok_or_else(|| format!("'{base}' has no repository path"))?;
            // Credentials embedded in the URL are refused rather than carried:
            // they would end up in .git/config, in a log line, and in any
            // object we build from this URL.
            if authority.contains('@') {
                return Err(
                    "refusing a URL with embedded credentials; configure a credential source instead"
                        .to_string(),
                );
            }
            let host = authority.to_string();
            let path = normalize_repo_path(path);
            if host.is_empty() || path.is_empty() {
                return Err(format!("'{base}' is not a complete repository URL"));
            }
            return Ok(Some(RemoteTarget {
                scheme: RemoteScheme::Https,
                url: format!("https://{host}/{path}.git"),
                host,
                path,
                reference,
            }));
        }
    }
    Ok(None)
}

fn parse_ssh(base: &str, reference: Option<String>) -> Result<Option<RemoteTarget>, String> {
    // ssh://git@host/owner/repo
    if let Some(rest) = base.strip_prefix("ssh://") {
        let (authority, path) = rest
            .split_once('/')
            .ok_or_else(|| format!("'{base}' has no repository path"))?;
        let host = authority
            .rsplit('@')
            .next()
            .unwrap_or(authority)
            .to_string();
        let path = normalize_repo_path(path);
        return Ok(Some(RemoteTarget {
            scheme: RemoteScheme::Ssh,
            url: format!("ssh://git@{host}/{path}.git"),
            host,
            path,
            reference,
        }));
    }

    // git@host:owner/repo — scp-like syntax, no scheme.
    if let Some((authority, path)) = base.split_once(':')
        && authority.contains('@')
        && !path.starts_with('/')
        && !authority.contains('/')
    {
        {
            let host = authority
                .rsplit('@')
                .next()
                .unwrap_or(authority)
                .to_string();
            let path = normalize_repo_path(path);
            if host.is_empty() || path.is_empty() {
                return Err(format!("'{base}' is not a complete repository reference"));
            }
            return Ok(Some(RemoteTarget {
                scheme: RemoteScheme::Ssh,
                url: format!("ssh://git@{host}/{path}.git"),
                host,
                path,
                reference,
            }));
        }
    }

    Ok(None)
}

/// `owner/repo`, assumed to be GitHub.
fn parse_shorthand(base: &str, reference: Option<String>) -> Option<RemoteTarget> {
    let path = normalize_repo_path(base);
    let mut segments = path.split('/');
    let owner = segments.next()?;
    let repo = segments.next()?;
    if segments.next().is_some() {
        return None;
    }
    let valid = |segment: &str| {
        !segment.is_empty()
            && segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
            && !segment.starts_with('.')
    };
    if !valid(owner) || !valid(repo) {
        return None;
    }

    Some(RemoteTarget {
        scheme: RemoteScheme::Https,
        host: "github.com".to_string(),
        url: format!("https://github.com/{owner}/{repo}.git"),
        path: format!("{owner}/{repo}"),
        reference,
    })
}

fn normalize_repo_path(path: &str) -> String {
    path.trim_matches('/')
        .trim_end_matches(".git")
        .trim_matches('/')
        .to_string()
}

/// True when an address must not be reached on a caller's behalf.
///
/// Once the server fetches URLs for callers it can be pointed at things the
/// caller cannot reach themselves — cloud metadata endpoints, internal
/// services, localhost. This is the classification half, kept free of DNS so
/// it can be tested exhaustively.
pub fn is_forbidden_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => is_forbidden_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_forbidden_v4(&mapped);
            }
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                // Unique local fc00::/7
                || (ip.octets()[0] & 0xfe) == 0xfc
                // Link-local fe80::/10
                || (ip.octets()[0] == 0xfe && (ip.octets()[1] & 0xc0) == 0x80)
        }
    }
}

fn is_forbidden_v4(ip: &Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        // Carrier-grade NAT, 100.64.0.0/10 — reaches provider infrastructure.
        || (a == 100 && (64..128).contains(&b))
        // Benchmarking, 198.18.0.0/15.
        || (a == 198 && (18..20).contains(&b))
}

/// Resolve a host and refuse it if any address it answers with is off limits.
///
/// Returns the addresses so a caller can connect to a *checked* address rather
/// than re-resolving, which would reopen the DNS-rebinding window between the
/// check and the connection.
pub fn resolve_and_check(
    host: &str,
    port: u16,
    allow_private: bool,
) -> Result<Vec<IpAddr>, String> {
    let addresses: Vec<IpAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|err| format!("could not resolve host '{host}': {err}"))?
        .map(|socket| socket.ip())
        .collect();

    if addresses.is_empty() {
        return Err(format!("host '{host}' resolved to no addresses"));
    }
    if allow_private {
        return Ok(addresses);
    }

    // Every address must be acceptable. A host that answers with one public and
    // one private address is exactly the shape a rebinding attack takes.
    if let Some(forbidden) = addresses
        .iter()
        .find(|address| is_forbidden_address(address))
    {
        return Err(format!(
            "refusing to clone from '{host}': it resolves to {forbidden}, a private or loopback address. Set AUDIT_ALLOW_PRIVATE_ADDRESSES=true only if this is a self-hosted git server you intend to reach."
        ));
    }

    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(target: &str) -> RemoteTarget {
        match parse(target).expect("should parse") {
            TargetExpression::Remote(remote) => remote,
            other => panic!("expected a remote target, got {other:?}"),
        }
    }

    #[test]
    fn an_existing_local_path_always_wins() {
        // The guarantee that no current caller's target changes meaning.
        let target = parse(env!("CARGO_MANIFEST_DIR")).expect("should parse");
        assert!(matches!(target, TargetExpression::LocalPath(_)));
        assert!(!target.is_remote());
    }

    #[test]
    fn parses_https_urls() {
        let parsed = remote("https://github.com/owner/repo");
        assert_eq!(parsed.scheme, RemoteScheme::Https);
        assert_eq!(parsed.host, "github.com");
        assert_eq!(parsed.path, "owner/repo");
        assert_eq!(parsed.url, "https://github.com/owner/repo.git");
        assert!(parsed.reference.is_none());

        // A trailing .git is normalized away, not doubled.
        assert_eq!(
            remote("https://gitlab.example.com/group/project.git").url,
            "https://gitlab.example.com/group/project.git"
        );
    }

    #[test]
    fn parses_both_ssh_forms() {
        let scp_like = remote("git@github.com:owner/repo.git");
        assert_eq!(scp_like.scheme, RemoteScheme::Ssh);
        assert_eq!(scp_like.host, "github.com");
        assert_eq!(scp_like.path, "owner/repo");

        let url_form = remote("ssh://git@git.example.com/owner/repo");
        assert_eq!(url_form.scheme, RemoteScheme::Ssh);
        assert_eq!(url_form.host, "git.example.com");
    }

    #[test]
    fn parses_owner_repo_shorthand_as_github() {
        let parsed = remote("mbround18/audit-mcp");
        assert_eq!(parsed.host, "github.com");
        assert_eq!(parsed.url, "https://github.com/mbround18/audit-mcp.git");
    }

    #[test]
    fn extracts_an_inline_reference() {
        assert_eq!(
            remote("https://github.com/owner/repo#main")
                .reference
                .as_deref(),
            Some("main")
        );
        assert_eq!(
            remote("owner/repo#v1.2.3").reference.as_deref(),
            Some("v1.2.3")
        );
        assert_eq!(
            remote("git@github.com:owner/repo#a1b2c3d")
                .reference
                .as_deref(),
            Some("a1b2c3d")
        );
    }

    #[test]
    fn refuses_credentials_embedded_in_a_url() {
        // They would land in .git/config and in every log line touching the URL.
        let error = parse("https://user:token@github.com/owner/repo").expect_err("should refuse");
        assert!(error.contains("embedded credentials"));
    }

    #[test]
    fn refuses_plaintext_http() {
        let error = parse("http://github.com/owner/repo").expect_err("should refuse");
        assert!(error.contains("plaintext"));
    }

    #[test]
    fn a_nonexistent_path_shaped_target_stays_a_path() {
        // Clearer to fail with "does not exist" than to misparse it as a repo.
        let target = parse("/definitely/not/here").expect("should parse");
        assert!(matches!(target, TargetExpression::LocalPath(_)));
        assert!(matches!(
            parse("./nope").expect("should parse"),
            TargetExpression::LocalPath(_)
        ));
    }

    #[test]
    fn rejects_unparseable_targets() {
        assert!(parse("").is_err());
        assert!(parse("   ").is_err());
        // Three segments is neither shorthand nor a URL.
        assert!(parse("a/b/c/d/e").is_err());
    }

    #[test]
    fn private_and_loopback_addresses_are_forbidden() {
        for address in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254", // cloud metadata, the classic SSRF target
            "0.0.0.0",
            "100.64.0.1", // carrier-grade NAT
            "198.18.0.1", // benchmarking
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1", // IPv4-mapped loopback
        ] {
            let parsed: IpAddr = address.parse().expect("valid address");
            assert!(
                is_forbidden_address(&parsed),
                "{address} should be forbidden"
            );
        }
    }

    #[test]
    fn public_addresses_are_allowed() {
        for address in ["140.82.121.4", "1.1.1.1", "2606:4700::1111"] {
            let parsed: IpAddr = address.parse().expect("valid address");
            assert!(
                !is_forbidden_address(&parsed),
                "{address} should be allowed"
            );
        }
    }

    #[test]
    fn the_private_address_opt_out_is_respected() {
        // Resolution of localhost is reliable enough to assert on.
        let refused = resolve_and_check("localhost", 443, false);
        assert!(refused.is_err(), "localhost must be refused by default");
        assert!(
            refused
                .unwrap_err()
                .contains("AUDIT_ALLOW_PRIVATE_ADDRESSES")
        );

        let allowed = resolve_and_check("localhost", 443, true);
        assert!(allowed.is_ok(), "the opt-out must permit it");
    }
}
