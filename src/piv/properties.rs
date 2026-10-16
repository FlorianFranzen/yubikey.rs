//! The application property template a PIV application answers SELECT with.
//!
//! NIST SP 800-73-4 Part 2, 3.1.1 defines it: the application identifier, an optional
//! label and URL, the cryptographic algorithms the card supports, and the coexistent tag
//! allocation authority. A YubiKey sends only the identifiers; other implementations
//! (trussed's piv-authenticator, which runs on the Nitrokey 3 and Solo 2) list their
//! algorithms, which is the one way a client can learn what such a card takes before it
//! writes anything to it.

use super::AlgorithmId;
use crate::{Error, Result, mgm::MgmAlgorithmId};

/// Application property template tag
const TAG_TEMPLATE: u16 = 0x61;
/// Application identifier (the PIX, with its version)
const TAG_AID: u16 = 0x4f;
/// Application label
const TAG_LABEL: u16 = 0x50;
/// Uniform resource locator
const TAG_URL: u16 = 0x5f50;
/// Cryptographic algorithms supported
const TAG_ALGORITHMS: u16 = 0xac;
/// One cryptographic algorithm identifier, within [`TAG_ALGORITHMS`]
const TAG_ALGORITHM: u16 = 0x80;

/// What a PIV application announces about itself when it is selected.
///
/// Captured once, when the card is opened, from the SELECT that every session starts with,
/// so reading it costs no command of its own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationProperties {
    aid: Vec<u8>,
    label: Option<String>,
    url: Option<String>,
    algorithms: Option<Vec<u8>>,
}

impl ApplicationProperties {
    /// Parse the data of a SELECT response: one application property template.
    pub fn parse(response: &[u8]) -> Result<Self> {
        let (tag, template, _) = read_tlv(response)?;
        if tag != TAG_TEMPLATE {
            return Err(Error::ParseError);
        }

        let mut properties = Self {
            aid: Vec::new(),
            label: None,
            url: None,
            algorithms: None,
        };
        let mut rest = template;
        while !rest.is_empty() {
            let (tag, value, next) = read_tlv(rest)?;
            match tag {
                TAG_AID => properties.aid = value.to_vec(),
                TAG_LABEL => properties.label = text(value),
                TAG_URL => properties.url = text(value),
                TAG_ALGORITHMS => {
                    let mut algorithms = Vec::new();
                    let mut entries = value;
                    while !entries.is_empty() {
                        let (tag, value, next) = read_tlv(entries)?;
                        // The list ends with an object identifier (06), which carries no
                        // algorithm
                        if tag == TAG_ALGORITHM {
                            let [id] = value else {
                                return Err(Error::ParseError);
                            };
                            algorithms.push(*id);
                        }
                        entries = next;
                    }
                    properties.algorithms = Some(algorithms);
                }
                // The coexistent tag allocation authority, and anything a later revision adds
                _ => {}
            }
            rest = next;
        }

        Ok(properties)
    }

    /// The application identifier the card reports: the PIX with its version, without the
    /// NIST RID, as SP 800-73-4 has it
    pub fn aid(&self) -> &[u8] {
        &self.aid
    }

    /// The application label, if the card sends one
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// The URL of the application's specification, if the card sends one
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// The algorithm identifiers the card lists as supported, asymmetric and management key
    /// algorithms alike, or `None` if it lists none at all (as a YubiKey does)
    pub fn algorithm_ids(&self) -> Option<&[u8]> {
        self.algorithms.as_deref()
    }

    /// Whether the card lists `algorithm`, or `None` if it lists nothing to go by
    pub fn supports(&self, algorithm: AlgorithmId) -> Option<bool> {
        self.lists(algorithm.into())
    }

    /// Whether the card lists `algorithm` for its management key, or `None` if it lists
    /// nothing to go by
    pub fn supports_management(&self, algorithm: MgmAlgorithmId) -> Option<bool> {
        self.lists(algorithm.into())
    }

    fn lists(&self, id: u8) -> Option<bool> {
        self.algorithms.as_ref().map(|ids| ids.contains(&id))
    }
}

/// Labels and URLs are informational; text that is not UTF-8 is dropped rather than failing
/// the whole template
fn text(value: &[u8]) -> Option<String> {
    std::str::from_utf8(value).ok().map(str::to_owned)
}

/// Read one BER-TLV with a one- or two-byte tag and a definite length, returning the tag,
/// the value and the rest of the buffer.
///
/// The crate's own TLV reader takes one-byte tags only, and the URL's tag (5F50) has two.
fn read_tlv(buffer: &[u8]) -> Result<(u16, &[u8], &[u8])> {
    let (&first, rest) = buffer.split_first().ok_or(Error::SizeError)?;
    let (tag, rest) = if first & 0x1f == 0x1f {
        let (&second, rest) = rest.split_first().ok_or(Error::SizeError)?;
        // A third tag byte would follow; nothing in this template uses one
        if second & 0x80 != 0 {
            return Err(Error::ParseError);
        }
        (u16::from_be_bytes([first, second]), rest)
    } else {
        (u16::from(first), rest)
    };

    let (&length, rest) = rest.split_first().ok_or(Error::SizeError)?;
    let (length, rest) = match length {
        0x00..=0x7f => (usize::from(length), rest),
        0x81 => {
            let (&length, rest) = rest.split_first().ok_or(Error::SizeError)?;
            (usize::from(length), rest)
        }
        0x82 => {
            let [high, low, rest @ ..] = rest else {
                return Err(Error::SizeError);
            };
            (usize::from(u16::from_be_bytes([*high, *low])), rest)
        }
        _ => return Err(Error::ParseError),
    };

    if rest.len() < length {
        return Err(Error::SizeError);
    }
    let (value, rest) = rest.split_at(length);
    Ok((tag, value, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hex with whitespace allowed, for readable recorded responses
    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        digits
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16)
                    .expect("hex digits")
            })
            .collect()
    }

    /// A YubiKey 5: the identifiers, nothing else
    const YUBIKEY: &str = "61 11 4f06000010000100 7907 4f05a000000308";

    /// trussed's piv-authenticator with its default label and URL (Nitrokey 3, Solo 2)
    const PIV_AUTHENTICATOR: &str = "61 6f
        4f06 000010000100
        500c 4e6974726f6b657920504956
        5f502d 68747470733a2f2f6769746875622e636f6d2f4e6974726f6b65792f7069762d61757468656e74696361746f72
        ac1e 800103 80010c 800111 800107 800105 800116 800114 8001e0 8001e1 060100
        7907 4f05a000000308";

    #[test]
    fn yubikey_lists_nothing() {
        let properties = ApplicationProperties::parse(&hex(YUBIKEY)).expect("a YubiKey template");
        assert_eq!(properties.aid(), hex("000010000100"));
        assert_eq!(properties.label(), None);
        assert_eq!(properties.algorithm_ids(), None);
        assert_eq!(properties.supports(AlgorithmId::EccP256), None);
        assert_eq!(properties.supports_management(MgmAlgorithmId::Aes256), None);
    }

    #[test]
    fn piv_authenticator_lists_its_algorithms() {
        let properties = ApplicationProperties::parse(&hex(PIV_AUTHENTICATOR))
            .expect("a piv-authenticator template");
        assert_eq!(properties.aid(), hex("000010000100"));
        assert_eq!(properties.label(), Some("Nitrokey PIV"));
        assert_eq!(
            properties.url(),
            Some("https://github.com/Nitrokey/piv-authenticator")
        );
        assert_eq!(
            properties.algorithm_ids(),
            Some(&hex("03 0c 11 07 05 16 14 e0 e1")[..])
        );
        assert_eq!(properties.supports(AlgorithmId::X25519), Some(true));
        assert_eq!(properties.supports(AlgorithmId::Rsa1024), Some(false));
        assert_eq!(
            properties.supports_management(MgmAlgorithmId::Aes256),
            Some(true)
        );
        assert_eq!(
            properties.supports_management(MgmAlgorithmId::Aes128),
            Some(false)
        );
    }

    #[test]
    fn rejects_truncated_and_foreign_templates() {
        assert!(ApplicationProperties::parse(&hex(PIV_AUTHENTICATOR)[..40]).is_err());
        assert!(ApplicationProperties::parse(&hex("62 00")).is_err());
        assert!(ApplicationProperties::parse(&[]).is_err());
    }
}
