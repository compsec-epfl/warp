//! Typed snapshot of the protocol's structural shape: `IOP::NAME` + ordered
//! `IOR (NAME, MESSAGE_TAGS, delegated_events)`. Complements the FS-bytes
//! snapshot. `delegated_events` names the orchestrator-emitted events the
//! IOR delegates (e.g. `vc.open_multiple`); useful for a future
//! BCS-style consumer that needs to consume opens at the right positions.

pub struct IorSchema {
    pub name: &'static str,
    pub message_tags: &'static [&'static str],
    /// Orchestrator-emitted events tied to this IOR (e.g. VC opens). Empty
    /// for IORs whose transcript activity is fully inside `prove_inner`.
    pub delegated_events: &'static [&'static str],
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
            hasher.update(b"DELEGATED:");
            for ev in ior.delegated_events {
                hasher.update(ev.as_bytes());
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
                out.push_str(&format!("        tag: {}\n", tag));
            }
            for ev in ior.delegated_events {
                out.push_str(&format!("        delegates: {}\n", ev));
            }
        }
        out
    }
}
