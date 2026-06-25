use std::fmt;

use crate::error::CrossNetError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Eui48([u8; 6]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Eui64([u8; 8]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum MacAddrInner {
    Eui48(Eui48),
    Eui64(Eui64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(MacAddrInner);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.to_string();
        write!(f, "{}", s)
    }
}

impl MacAddr {
    /// Creates a new MAC address from the given bytes.
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        let eui48 = Eui48([a, b, c, d, e, f]);
        MacAddr(MacAddrInner::Eui48(eui48))
    }
    pub fn zero() -> Self {
        let eui48 = Eui48([0, 0, 0, 0, 0, 0]);
        MacAddr(MacAddrInner::Eui48(eui48))
    }
    /// Creates a new EUI-48 MAC address from the given bytes.
    pub fn new_eui48(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        let eui48 = Eui48([a, b, c, d, e, f]);
        MacAddr(MacAddrInner::Eui48(eui48))
    }
    /// Creates a new EUI-64 MAC address from the given bytes.
    pub fn new_eui64(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8) -> Self {
        let egui64 = Eui64([a, b, c, d, e, f, g, h]);
        MacAddr(MacAddrInner::Eui64(egui64))
    }
    pub fn from_str(s: &str) -> Result<Self, CrossNetError> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() > 8 {
            return Err(CrossNetError::ParseMacAddrErr { mac: s.to_string() });
        } else if parts.len() == 8 {
            let mut bytes = [0u8; 8];
            for (i, part) in parts.iter().enumerate() {
                match u8::from_str_radix(part, 16) {
                    Ok(b) => bytes[i] = b,
                    Err(_e) => {
                        return Err(CrossNetError::ParseMacAddrErr { mac: s.to_string() });
                    }
                }
            }
            let eui64 = Eui64(bytes);
            Ok(MacAddr(MacAddrInner::Eui64(eui64)))
        } else if parts.len() == 6 {
            let mut bytes = [0u8; 6];
            for (i, part) in parts.iter().enumerate() {
                match u8::from_str_radix(part, 16) {
                    Ok(b) => bytes[i] = b,
                    Err(_e) => {
                        return Err(CrossNetError::ParseMacAddrErr { mac: s.to_string() });
                    }
                }
            }
            let eui48 = Eui48(bytes);
            Ok(MacAddr(MacAddrInner::Eui48(eui48)))
        } else {
            Err(CrossNetError::ParseMacAddrErr { mac: s.to_string() })
        }
    }
    pub fn to_string(&self) -> String {
        let mut parts = Vec::new();
        match &self.0 {
            MacAddrInner::Eui48(eui48) => {
                for b in &eui48.0 {
                    parts.push(format!("{:02x}", b));
                }
            }
            MacAddrInner::Eui64(eui64) => {
                for b in &eui64.0 {
                    parts.push(format!("{:02x}", b));
                }
            }
        }
        parts.join(":")
    }
    pub fn octets(&self) -> Vec<u8> {
        match &self.0 {
            MacAddrInner::Eui48(eui48) => eui48.0.to_vec(),
            MacAddrInner::Eui64(eui64) => eui64.0.to_vec(),
        }
    }
    pub fn is_eui48(&self) -> bool {
        matches!(self.0, MacAddrInner::Eui48(_))
    }
    pub fn is_eui64(&self) -> bool {
        matches!(self.0, MacAddrInner::Eui64(_))
    }
}
