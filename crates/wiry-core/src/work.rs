//! Operation counts for the reassemblers' inserts, so a test can assert that
//! one arrival does not cost what is already held.
//!
//! A clock cannot guard that: the quadratic case shows as ~16x growth over 4x
//! the input, and wall-clock noise on a loaded machine is wider than the margin
//! under 16. Entries examined and octets copied are deterministic.
//!
//! Outside `cfg(test)` this is zero-sized and every method is empty.

#[derive(Default)]
pub(crate) struct Work {
    /// Entries touched: held segments probed, ranges walked, queue entries
    /// swept, list entries shifted by an insertion.
    #[cfg(test)]
    probes: u64,
    /// Octets copied. Concatenating what is held would move a whole buffer per
    /// arrival rather than one segment.
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

    /// Moves `other`'s counts into `self`, leaving `other` at zero.
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
