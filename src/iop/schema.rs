//! Typed snapshot of the protocol's structural shape: `IOP::NAME` + ordered
//! `IOR (NAME, MESSAGE_TAGS)`. Complements the FS-bytes snapshot.

pub struct IorSchema {
    pub name: &'static str,
    pub message_tags: &'static [&'static str],
}

pub struct ProtocolSchema {
    pub iop_name: &'static str,
    pub iors: Vec<IorSchema>,
}

impl ProtocolSchema {
    /// Stable hash for snapshot tests. Order-sensitive, tag-sensitive.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"IOP:");
        hasher.update(self.iop_name.as_bytes());
        hasher.update(b"|");
        for ior in &self.iors {
            hasher.update(b"IOR:");
            hasher.update(ior.name.as_bytes());
            hasher.update(b"|TAGS:");
            for tag in ior.message_tags {
                hasher.update(tag.as_bytes());
                hasher.update(b"|");
            }
        }
        *hasher.finalize().as_bytes()
    }

    /// Human-readable dump for debugging and spec docs.
    pub fn display(&self) -> String {
        let mut out = format!("ProtocolSchema(iop={})\n", self.iop_name);
        for (i, ior) in self.iors.iter().enumerate() {
            out.push_str(&format!("  [{}] {}\n", i, ior.name));
            for tag in ior.message_tags {
                out.push_str(&format!("        {}\n", tag));
            }
        }
        out
    }
}
