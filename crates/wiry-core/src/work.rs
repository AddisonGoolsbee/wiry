//! What a reassembler's inserts cost, counted rather than timed.
//!
//! Both reassemblers here promise that one arrival does not cost what is
//! already held: `frag.rs` says so of its received-range list, `stream.rs` of
//! its held-segment map. Each promise has already been broken once — the range
//! list was re-sorted per fragment and one crafted datagram took 21.5s against
//! 0.18s for a real capture of the same size.
//!
//! A clock cannot guard that. The defect shows as ~16x growth over 4x the
//! input, so a threshold has to sit under 16 to catch it, and wall-clock noise
//! on a loaded machine is wider than the room left below. The quantity that
//! actually blows up is operations: entries examined, and octets copied. Those
//! are deterministic and a busy machine cannot move them.
//!
//! Outside `cfg(test)` this is a zero-sized type whose every method has an
//! empty body, so nothing is added to the path being measured.

#[derive(Default)]
pub(crate) struct Work {
    /// Entries examined: held segments probed, ranges walked, queue entries
    /// swept. One unit is one step a scan-everything implementation would
    /// multiply.
    #[cfg(test)]
    probes: u64,
    /// Octets copied into a buffer. An implementation that concatenated what it
    /// holds would move a whole buffer per arrival instead of a segment.
    #[cfg(test)]
    bytes: u64,
}

impl Work {
    #[inline(always)]
    pub(crate) fn probe(&mut self) {
        #[cfg(test)]
        {
            self.probes += 1;
        }
    }

    #[inline(always)]
    pub(crate) fn probes(&mut self, _n: usize) {
        #[cfg(test)]
        {
            self.probes += _n as u64;
        }
    }

    #[inline(always)]
    pub(crate) fn copied(&mut self, _n: usize) {
        #[cfg(test)]
        {
            self.bytes += _n as u64;
        }
    }

    /// Move `other`'s count in, so a counter kept per stream can be gathered
    /// where the run can read it.
    #[inline(always)]
    pub(crate) fn absorb(&mut self, _other: &mut Work) {
        #[cfg(test)]
        {
            self.probes += std::mem::take(&mut _other.probes);
            self.bytes += std::mem::take(&mut _other.bytes);
        }
    }

    #[cfg(test)]
    pub(crate) fn counts(&self) -> (u64, u64) {
        (self.probes, self.bytes)
    }
}
