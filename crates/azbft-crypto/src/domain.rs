#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Domain {
    Vote,
    Timeout,
    Proposal,
    #[cfg(feature = "host-extensions")]
    Handshake,
    Reconfig,
    AppHash,
    /// Reserved host discovery domain with stable tag 7.
    #[cfg(feature = "host-extensions")]
    NameRecord,
    /// Reserved host liveness domain with stable tag 8.
    #[cfg(feature = "host-extensions")]
    PingPong,
}

impl Domain {
    pub fn tag(self) -> u8 {
        match self {
            Domain::Vote => 1,
            Domain::Timeout => 2,
            Domain::Proposal => 3,
            #[cfg(feature = "host-extensions")]
            Domain::Handshake => 4,
            Domain::Reconfig => 5,
            Domain::AppHash => 6,
            #[cfg(feature = "host-extensions")]
            Domain::NameRecord => 7,
            #[cfg(feature = "host-extensions")]
            Domain::PingPong => 8,
        }
    }
}

/// Domain-separated digest = blake3(tag ‖ msg).
pub fn digest(d: Domain, msg: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[d.tag()]);
    h.update(msg);
    *h.finalize().as_bytes()
}

#[cfg(all(test, feature = "host-extensions"))]
mod host_extension_tests {
    use super::*;

    #[test]
    fn reserved_domain_tags_are_7_and_8() {
        assert_eq!(Domain::NameRecord.tag(), 7);
        assert_eq!(Domain::PingPong.tag(), 8);
        let existing = [
            Domain::Vote,
            Domain::Timeout,
            Domain::Proposal,
            Domain::Handshake,
            Domain::Reconfig,
            Domain::AppHash,
        ];
        for domain in existing {
            assert_ne!(domain.tag(), 7);
            assert_ne!(domain.tag(), 8);
        }
        assert_ne!(Domain::NameRecord.tag(), Domain::PingPong.tag());
    }
}
