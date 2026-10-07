//! Agent credentials: who may act, for which identity. Reloaded on SIGHUP.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use nostr::key::PublicKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentsFile {
    agents: Vec<AgentEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentEntry {
    name: String,
    /// npub or hex.
    identity: String,
    token_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    pub name: String,
    pub identity: PublicKey,
}

/// Agents indexed by token hash. Immutable: a reload builds a new one.
#[derive(Debug, Default)]
pub struct Agents {
    by_token: HashMap<String, Agent>,
}

impl Agents {
    pub fn load(path: impl AsRef<Path>, served: &HashSet<PublicKey>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read agents at {}", path.display()))?;
        Self::from_json(&raw, served)
            .with_context(|| format!("invalid agents at {}", path.display()))
    }

    pub fn from_json(raw: &str, served: &HashSet<PublicKey>) -> Result<Self> {
        let file: AgentsFile = serde_json::from_str(raw)?;

        let mut names = HashSet::new();
        let mut by_token = HashMap::new();
        for entry in file.agents {
            let name = entry.name;
            if !names.insert(name.clone()) {
                bail!("agent `{name}` is listed twice");
            }
            let identity = PublicKey::parse(&entry.identity)
                .with_context(|| format!("agent `{name}`: invalid identity"))?;
            if !served.contains(&identity) {
                bail!("agent `{name}`: identity {identity} is not served by this bunker");
            }
            let hash = entry.token_sha256.to_ascii_lowercase();
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("agent `{name}`: token_sha256 must be 64 hex characters");
            }
            if by_token.insert(hash, Agent { name, identity }).is_some() {
                bail!("two agents share a token_sha256");
            }
        }
        Ok(Self { by_token })
    }

    pub fn get(&self, token_hash: &str) -> Option<&Agent> {
        self.by_token.get(token_hash)
    }
}

/// SHA-256, lowercase hex. A fast hash is enough: tokens are 256 random bits, not
/// passwords, and `approve` must not block.
pub fn token_hash(secret: &str) -> String {
    format!("{:x}", Sha256::digest(secret.as_bytes()))
}

/// Fails closed: an invalid file revokes every agent. Keeping the old list would keep
/// alive an agent that a broken edit meant to revoke.
pub fn reload(path: impl AsRef<Path>, served: &HashSet<PublicKey>) -> Agents {
    match Agents::load(&path, served) {
        Ok(agents) => {
            tracing::info!(path = %path.as_ref().display(), "agents reloaded");
            agents
        }
        Err(e) => {
            tracing::error!(
                error = %format!("{e:#}"),
                "agents rejected: every agent is revoked until the file is fixed"
            );
            Agents::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use nostr::key::Keys;

    use super::*;

    fn served() -> (PublicKey, HashSet<PublicKey>) {
        let identity = Keys::generate().public_key();
        (identity, HashSet::from([identity]))
    }

    fn file(identity: &PublicKey, entries: &[(&str, &str)]) -> String {
        let agents: Vec<_> = entries
            .iter()
            .map(|(name, token)| {
                serde_json::json!({
                    "name": name,
                    "identity": identity.to_hex(),
                    "token_sha256": token_hash(token),
                })
            })
            .collect();
        serde_json::json!({ "agents": agents }).to_string()
    }

    #[test]
    fn finds_an_agent_by_its_token() {
        let (identity, served) = served();
        let agents = Agents::from_json(&file(&identity, &[("bot", "t0ken")]), &served).unwrap();

        let agent = agents.get(&token_hash("t0ken")).unwrap();
        assert_eq!(agent.name, "bot");
        assert_eq!(agent.identity, identity);
        assert!(agents.get(&token_hash("wrong")).is_none());
    }

    #[test]
    fn accepts_an_npub_and_an_uppercase_hash() {
        use nostr::nips::nip19::ToBech32;

        let (identity, served) = served();
        let raw = serde_json::json!({ "agents": [{
            "name": "bot",
            "identity": identity.to_bech32().unwrap(),
            "token_sha256": token_hash("t0ken").to_uppercase(),
        }]})
        .to_string();

        let agents = Agents::from_json(&raw, &served).unwrap();
        assert!(agents.get(&token_hash("t0ken")).is_some());
    }

    #[test]
    fn an_empty_list_is_valid_and_trusts_nobody() {
        let (_, served) = served();
        let agents = Agents::from_json(r#"{ "agents": [] }"#, &served).unwrap();
        assert!(agents.get(&token_hash("")).is_none());
    }

    #[test]
    fn rejects_an_identity_the_bunker_does_not_serve() {
        let (_, served) = served();
        let stranger = Keys::generate().public_key();
        assert!(Agents::from_json(&file(&stranger, &[("bot", "t0ken")]), &served).is_err());
    }

    #[test]
    fn rejects_a_duplicate_name() {
        let (identity, served) = served();
        let raw = file(&identity, &[("bot", "one"), ("bot", "two")]);
        assert!(Agents::from_json(&raw, &served).is_err());
    }

    #[test]
    fn rejects_a_shared_token() {
        let (identity, served) = served();
        let raw = file(&identity, &[("a", "same"), ("b", "same")]);
        assert!(Agents::from_json(&raw, &served).is_err());
    }

    #[test]
    fn rejects_a_malformed_hash() {
        let (identity, served) = served();
        let raw = file(&identity, &[("bot", "t0ken")]).replace(&token_hash("t0ken"), "abc");
        assert!(Agents::from_json(&raw, &served).is_err());
    }

    #[test]
    fn rejects_a_misspelt_field() {
        let (identity, served) = served();
        let raw = file(&identity, &[("bot", "t0ken")]).replace("token_sha256", "token_sha");
        assert!(Agents::from_json(&raw, &served).is_err());
    }

    #[test]
    fn token_hash_is_the_sha256_shasum_prints() {
        // printf '%s' abc | shasum -a 256
        assert_eq!(
            token_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn a_broken_file_on_reload_revokes_everyone() {
        let (identity, served) = served();
        let path = std::env::temp_dir().join(format!("c2-reload-{}.json", std::process::id()));

        std::fs::write(&path, file(&identity, &[("bot", "t0ken")])).unwrap();
        assert!(reload(&path, &served).get(&token_hash("t0ken")).is_some());

        std::fs::write(&path, "{ \"agents\": [ ").unwrap();
        assert!(reload(&path, &served).get(&token_hash("t0ken")).is_none());

        std::fs::remove_file(&path).unwrap();
    }
}
