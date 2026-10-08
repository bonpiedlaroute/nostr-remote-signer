//! What the bunker's own transport relay admits: NIP-46 traffic for this bunker only, at a
//! bounded rate.

use std::collections::HashSet;
use std::future::{Future, ready};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

use nostr_sdk::prelude::*;

use crate::rate::{RateConfig, RateLimiter};

#[derive(Debug)]
pub struct BunkerOnly {
    signers: HashSet<PublicKey>,
    per_ip: RateLimiter<IpAddr>,
    /// Bounds what the vault can be made to decrypt, whatever the number of sources.
    global: RateLimiter<()>,
}

impl BunkerOnly {
    /// `signers`: the transport keys of the bunker:// URIs.
    pub fn new(signers: HashSet<PublicKey>, per_ip: RateConfig, global: RateConfig) -> Self {
        Self {
            signers,
            per_ip: RateLimiter::new(per_ip),
            global: RateLimiter::new(global),
        }
    }

    fn admit(&self, event: &Event, ip: IpAddr) -> WritePolicyResult {
        if event.kind != Kind::NostrConnect {
            return WritePolicyResult::reject(MachineReadablePrefix::Blocked, "NIP-46 only");
        }
        // Answers from the bunker: unforgeable, since the relay checks the signature before
        // this policy, and never throttled, so a flood cannot silence them.
        if self.signers.contains(&event.pubkey) {
            return WritePolicyResult::Accept;
        }
        if !event.tags.public_keys().any(|p| self.signers.contains(&p)) {
            return WritePolicyResult::reject(
                MachineReadablePrefix::Blocked,
                "not for this bunker",
            );
        }
        if !self.per_ip.check(&ip) || !self.global.check(&()) {
            return WritePolicyResult::reject(MachineReadablePrefix::RateLimited, "slow down");
        }
        WritePolicyResult::Accept
    }
}

impl WritePolicy for BunkerOnly {
    fn admit_event<'a>(
        &'a self,
        event: &'a Event,
        addr: &'a SocketAddr,
    ) -> Pin<Box<dyn Future<Output = WritePolicyResult> + Send + 'a>> {
        Box::pin(ready(self.admit(event, addr.ip())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOOSE: RateConfig = RateConfig {
        burst: 100,
        per_second: 0.001,
    };
    const ONE: RateConfig = RateConfig {
        burst: 1,
        per_second: 0.001,
    };

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    fn event(kind: Kind, author: &Keys, to: PublicKey) -> Event {
        EventBuilder::new(kind, "opaque")
            .tag(Tag::public_key(to))
            .finalize(author)
            .unwrap()
    }

    fn request(signer: &Keys) -> Event {
        event(Kind::NostrConnect, &Keys::generate(), signer.public_key())
    }

    fn policy(signer: &Keys, per_ip: RateConfig, global: RateConfig) -> BunkerOnly {
        BunkerOnly::new(HashSet::from([signer.public_key()]), per_ip, global)
    }

    #[test]
    fn admits_a_request_to_the_bunker() {
        let signer = Keys::generate();
        let p = policy(&signer, LOOSE, LOOSE);
        assert!(p.admit(&request(&signer), ip(1)).is_accept());
    }

    #[test]
    fn rejects_any_other_kind() {
        let signer = Keys::generate();
        let p = policy(&signer, LOOSE, LOOSE);
        let note = event(Kind::TextNote, &Keys::generate(), signer.public_key());
        assert!(p.admit(&note, ip(1)).is_reject());
    }

    #[test]
    fn rejects_traffic_for_another_signer() {
        let signer = Keys::generate();
        let p = policy(&signer, LOOSE, LOOSE);
        let elsewhere = request(&Keys::generate());
        assert!(p.admit(&elsewhere, ip(1)).is_reject());
    }

    #[test]
    fn throttles_one_source_without_starving_the_others() {
        let signer = Keys::generate();
        let p = policy(&signer, ONE, LOOSE);
        assert!(p.admit(&request(&signer), ip(1)).is_accept());
        assert!(p.admit(&request(&signer), ip(1)).is_reject());
        assert!(p.admit(&request(&signer), ip(2)).is_accept());
    }

    #[test]
    fn many_sources_cannot_escape_the_global_limit() {
        let signer = Keys::generate();
        let p = policy(&signer, LOOSE, ONE);
        assert!(p.admit(&request(&signer), ip(1)).is_accept());
        assert!(p.admit(&request(&signer), ip(2)).is_reject());
    }

    #[test]
    fn the_bunker_answers_even_during_a_flood() {
        let signer = Keys::generate();
        let p = policy(&signer, ONE, ONE);
        assert!(p.admit(&request(&signer), ip(1)).is_accept());
        assert!(p.admit(&request(&signer), ip(1)).is_reject());

        let answer = event(Kind::NostrConnect, &signer, Keys::generate().public_key());
        assert!(p.admit(&answer, ip(1)).is_accept());
    }
}
