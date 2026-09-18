//! Generators: one declaration that multiplies into many packets.

/// splitmix64. Seedable, so a fuzz run can be repeated.
#[derive(Clone, Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_u128(&mut self) -> u128 {
        (u128::from(self.next_u64()) << 64) | u128::from(self.next_u64())
    }

    pub fn in_range(&mut self, lo: u64, hi: u64) -> u64 {
        if lo >= hi {
            return lo;
        }
        let span = hi - lo;
        if span == u64::MAX {
            return self.next_u64();
        }
        lo + ((u128::from(self.next_u64()) * u128::from(span + 1)) >> 64) as u64
    }

    fn in_range_wide(&mut self, lo: u128, hi: u128) -> u128 {
        if lo >= hi {
            return lo;
        }
        let span = hi - lo;
        if span == u128::MAX {
            return self.next_u128();
        }
        lo + self.next_u128() % (span + 1)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenVal {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
}

/// Wider than 8 octets has to travel as bytes; narrower fits the integer path.
fn addr_val(n: u128, width: usize) -> GenVal {
    if width <= 8 {
        return GenVal::Uint(n as u64);
    }
    let be = n.to_be_bytes();
    GenVal::Bytes(be[16 - width.min(16)..].to_vec())
}

#[derive(Clone, Debug)]
pub enum Gen {
    One(GenVal),
    Range {
        lo: u64,
        hi: u64,
    },
    Addrs {
        lo: u128,
        hi: u128,
        width: usize,
    },
    /// Concatenation, so `[1, 2, (5, 9)]` is seven values rather than three.
    Seq(Vec<Gen>),
    RandNum {
        lo: u64,
        hi: u64,
    },
    RandAddr {
        lo: u128,
        hi: u128,
        width: usize,
    },
    RandBytes {
        lo: usize,
        hi: usize,
        alphabet: Option<Vec<u8>>,
    },
    RandPick(Vec<GenVal>),
}

impl Gen {
    /// A volatile generator yields a fresh value per packet, so it multiplies
    /// by one.
    pub fn count(&self) -> u128 {
        match self {
            Gen::One(_) => 1,
            Gen::Range { lo, hi } => {
                if hi < lo {
                    0
                } else {
                    u128::from(hi - lo) + 1
                }
            }
            Gen::Addrs { lo, hi, .. } => {
                if hi < lo {
                    0
                } else {
                    (hi - lo).saturating_add(1)
                }
            }
            Gen::Seq(parts) => parts.iter().fold(0u128, |a, g| a.saturating_add(g.count())),
            _ => 1,
        }
    }

    pub fn at(&self, index: u128, rng: &mut Rng) -> GenVal {
        match self {
            Gen::One(v) => v.clone(),
            Gen::Range { lo, hi } => GenVal::Uint(
                lo.saturating_add(index.min(u128::from(hi.saturating_sub(*lo))) as u64),
            ),
            Gen::Addrs { lo, hi, width } => {
                addr_val(lo.saturating_add(index.min(hi.saturating_sub(*lo))), *width)
            }
            Gen::Seq(parts) => {
                let mut left = index;
                for g in parts {
                    let n = g.count();
                    if left < n {
                        return g.at(left, rng);
                    }
                    left -= n;
                }
                parts
                    .last()
                    .map(|g| g.at(0, rng))
                    .unwrap_or(GenVal::Uint(0))
            }
            Gen::RandNum { lo, hi } => GenVal::Uint(rng.in_range(*lo, *hi)),
            Gen::RandAddr { lo, hi, width } => addr_val(rng.in_range_wide(*lo, *hi), *width),
            Gen::RandBytes { lo, hi, alphabet } => {
                let n = rng.in_range(*lo as u64, *hi as u64) as usize;
                let mut out = Vec::with_capacity(n);
                for _ in 0..n {
                    out.push(match alphabet {
                        Some(a) if !a.is_empty() => a[rng.in_range(0, a.len() as u64 - 1) as usize],
                        _ => rng.next_u64() as u8,
                    });
                }
                GenVal::Bytes(out)
            }
            Gen::RandPick(vals) => {
                if vals.is_empty() {
                    return GenVal::Uint(0);
                }
                vals[rng.in_range(0, vals.len() as u64 - 1) as usize].clone()
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Slot {
    pub layer: usize,
    pub name: String,
    pub gen: Gen,
}

/// The generator fields of one template, ordered slowest-varying first.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    pub slots: Vec<Slot>,
}

impl Plan {
    /// Scapy's order: within a layer the last field declared varies slowest,
    /// and an enclosing layer varies slower than the one it carries. `rank` is
    /// the field's position in its protocol's table.
    pub fn new(mut slots: Vec<(Slot, usize)>) -> Self {
        slots.sort_by_key(|(s, rank)| (s.layer, std::cmp::Reverse(*rank)));
        Plan {
            slots: slots.into_iter().map(|(s, _)| s).collect(),
        }
    }

    pub fn count(&self) -> u128 {
        self.slots
            .iter()
            .fold(1u128, |a, s| a.saturating_mul(s.gen.count()))
    }

    /// The last slot varies fastest.
    pub fn values_at(&self, index: u128, rng: &mut Rng) -> Vec<(usize, &str, GenVal)> {
        let mut out = Vec::with_capacity(self.slots.len());
        let mut left = index;
        let mut digits = Vec::with_capacity(self.slots.len());
        for s in self.slots.iter().rev() {
            let n = s.gen.count().max(1);
            digits.push(left % n);
            left /= n;
        }
        for (s, d) in self.slots.iter().zip(digits.into_iter().rev()) {
            out.push((s.layer, s.name.as_str(), s.gen.at(d, rng)));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(layer: usize, name: &str, rank: usize, gen: Gen) -> (Slot, usize) {
        (
            Slot {
                layer,
                name: name.into(),
                gen,
            },
            rank,
        )
    }

    #[test]
    fn range_counts_inclusively() {
        assert_eq!(Gen::Range { lo: 5, hi: 10 }.count(), 6);
        assert_eq!(Gen::Range { lo: 5, hi: 5 }.count(), 1);
    }

    #[test]
    fn a_sequence_concatenates() {
        let g = Gen::Seq(vec![
            Gen::One(GenVal::Uint(1)),
            Gen::One(GenVal::Uint(2)),
            Gen::Range { lo: 5, hi: 9 },
        ]);
        assert_eq!(g.count(), 7);
        let mut rng = Rng::new(1);
        let got: Vec<_> = (0..7).map(|i| g.at(i, &mut rng)).collect();
        assert_eq!(
            got,
            vec![1, 2, 5, 6, 7, 8, 9]
                .into_iter()
                .map(GenVal::Uint)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_last_field_of_a_layer_varies_slowest() {
        let plan = Plan::new(vec![
            slot(0, "ttl", 7, Gen::Range { lo: 1, hi: 2 }),
            slot(0, "dst", 11, Gen::Range { lo: 3, hi: 4 }),
            slot(1, "dport", 1, Gen::Range { lo: 80, hi: 81 }),
        ]);
        assert_eq!(plan.count(), 8);
        let names: Vec<&str> = plan.slots.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["dst", "ttl", "dport"]);
        let mut rng = Rng::new(0);
        let seq: Vec<Vec<u64>> = (0..8)
            .map(|i| {
                plan.values_at(i, &mut rng)
                    .into_iter()
                    .map(|(_, _, v)| match v {
                        GenVal::Uint(n) => n,
                        _ => unreachable!(),
                    })
                    .collect()
            })
            .collect();
        assert_eq!(seq[0], vec![3, 1, 80]);
        assert_eq!(seq[1], vec![3, 1, 81]);
        assert_eq!(seq[2], vec![3, 2, 80]);
        assert_eq!(seq[4], vec![4, 1, 80]);
    }

    #[test]
    fn a_huge_product_does_not_overflow() {
        let all = Gen::Addrs {
            lo: 0,
            hi: u32::MAX as u128,
            width: 4,
        };
        let plan = Plan::new(vec![
            slot(0, "src", 10, all.clone()),
            slot(0, "dst", 11, all),
        ]);
        assert_eq!(plan.count(), 1u128 << 64);
    }

    #[test]
    fn a_product_too_wide_for_u128_saturates_upward_and_never_wraps() {
        let whole = || Gen::Addrs {
            lo: 0,
            hi: u128::MAX,
            width: 16,
        };
        // 2**128 addresses is one more than a u128 holds, so the widest single
        // span is short by one and every wider product pins at the ceiling.
        // What must never happen is a huge product reporting a small count and
        // slipping under a caller's eager-expansion threshold.
        assert_eq!(whole().count(), u128::MAX);
        for n in 1..=4 {
            let slots = (0..n).map(|i| slot(0, "dst", i, whole())).collect();
            assert_eq!(Plan::new(slots).count(), u128::MAX);
        }
        let mixed = Plan::new(vec![
            slot(0, "src", 10, whole()),
            slot(0, "dst", 11, Gen::Range { lo: 0, hi: 9 }),
        ]);
        assert_eq!(mixed.count(), u128::MAX);
        assert!(mixed.count() > 1 << 20);
    }

    #[test]
    fn no_generator_the_facade_can_build_counts_zero() {
        // A zero slot would zero the product and make a huge template read as
        // empty. Every empty spelling is refused in Python before it gets here.
        assert_eq!(Gen::Range { lo: 5, hi: 5 }.count(), 1);
        assert_eq!(
            Gen::Addrs {
                lo: 7,
                hi: 7,
                width: 4
            }
            .count(),
            1
        );
        assert_eq!(Gen::RandNum { lo: 0, hi: 9 }.count(), 1);
        assert_eq!(Gen::One(GenVal::Uint(3)).count(), 1);
    }

    #[test]
    fn a_volatile_field_multiplies_by_one_and_moves() {
        let g = Gen::RandNum { lo: 0, hi: 65535 };
        assert_eq!(g.count(), 1);
        let mut rng = Rng::new(7);
        let a = g.at(0, &mut rng);
        let b = g.at(0, &mut rng);
        assert_ne!(a, b);
    }

    #[test]
    fn the_same_seed_repeats_a_run() {
        let g = Gen::RandBytes {
            lo: 4,
            hi: 4,
            alphabet: None,
        };
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        assert_eq!(g.at(0, &mut a), g.at(0, &mut b));
    }

    #[test]
    fn a_wide_address_travels_as_bytes() {
        let g = Gen::Addrs {
            lo: 1,
            hi: 4,
            width: 16,
        };
        let mut rng = Rng::new(0);
        assert_eq!(
            g.at(2, &mut rng),
            GenVal::Bytes(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3])
        );
    }

    #[test]
    fn a_random_range_stays_inside_it() {
        let mut rng = Rng::new(3);
        for _ in 0..1000 {
            let v = rng.in_range(10, 12);
            assert!((10..=12).contains(&v));
        }
        assert_eq!(rng.in_range(5, 5), 5);
    }
}
