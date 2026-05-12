//! Thread-local op counters for crate-boundary events (Merkle ops, MLE
//! materialisations, sumcheck rounds). No-op without the `profile` feature.

#[cfg(feature = "profile")]
use std::cell::Cell;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Counter {
    EncodeCalls,
    MerkleTreeBuilds,
    MerklePathsGenerated,
    MerklePathsVerified,
    MleMaterializations,
    OracleLeafQueries,
    OraclePointQueries,
    TwinConstraintRounds,
    BatchingRounds,
    OodPointQueries,
}

impl Counter {
    pub const ALL: &'static [Counter] = &[
        Counter::EncodeCalls,
        Counter::MerkleTreeBuilds,
        Counter::MerklePathsGenerated,
        Counter::MerklePathsVerified,
        Counter::MleMaterializations,
        Counter::OracleLeafQueries,
        Counter::OraclePointQueries,
        Counter::TwinConstraintRounds,
        Counter::BatchingRounds,
        Counter::OodPointQueries,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Counter::EncodeCalls => "encode_calls",
            Counter::MerkleTreeBuilds => "merkle_tree_builds",
            Counter::MerklePathsGenerated => "merkle_paths_generated",
            Counter::MerklePathsVerified => "merkle_paths_verified",
            Counter::MleMaterializations => "mle_materializations",
            Counter::OracleLeafQueries => "oracle_leaf_queries",
            Counter::OraclePointQueries => "oracle_point_queries",
            Counter::TwinConstraintRounds => "twin_constraint_rounds",
            Counter::BatchingRounds => "batching_rounds",
            Counter::OodPointQueries => "ood_point_queries",
        }
    }
}

#[cfg(feature = "profile")]
thread_local! {
    static COUNTERS: Counters = const { Counters::new() };
}

#[cfg(feature = "profile")]
struct Counters {
    encode_calls: Cell<u64>,
    merkle_tree_builds: Cell<u64>,
    merkle_paths_generated: Cell<u64>,
    merkle_paths_verified: Cell<u64>,
    mle_materializations: Cell<u64>,
    oracle_leaf_queries: Cell<u64>,
    oracle_point_queries: Cell<u64>,
    twin_constraint_rounds: Cell<u64>,
    batching_rounds: Cell<u64>,
    ood_point_queries: Cell<u64>,
}

#[cfg(feature = "profile")]
impl Counters {
    const fn new() -> Self {
        Self {
            encode_calls: Cell::new(0),
            merkle_tree_builds: Cell::new(0),
            merkle_paths_generated: Cell::new(0),
            merkle_paths_verified: Cell::new(0),
            mle_materializations: Cell::new(0),
            oracle_leaf_queries: Cell::new(0),
            oracle_point_queries: Cell::new(0),
            twin_constraint_rounds: Cell::new(0),
            batching_rounds: Cell::new(0),
            ood_point_queries: Cell::new(0),
        }
    }

    fn cell(&self, c: Counter) -> &Cell<u64> {
        match c {
            Counter::EncodeCalls => &self.encode_calls,
            Counter::MerkleTreeBuilds => &self.merkle_tree_builds,
            Counter::MerklePathsGenerated => &self.merkle_paths_generated,
            Counter::MerklePathsVerified => &self.merkle_paths_verified,
            Counter::MleMaterializations => &self.mle_materializations,
            Counter::OracleLeafQueries => &self.oracle_leaf_queries,
            Counter::OraclePointQueries => &self.oracle_point_queries,
            Counter::TwinConstraintRounds => &self.twin_constraint_rounds,
            Counter::BatchingRounds => &self.batching_rounds,
            Counter::OodPointQueries => &self.ood_point_queries,
        }
    }
}

#[cfg(feature = "profile")]
#[inline]
pub fn bump(c: Counter, n: u64) {
    COUNTERS.with(|cs| {
        let cell = cs.cell(c);
        cell.set(cell.get().saturating_add(n));
    });
}

#[cfg(not(feature = "profile"))]
#[inline]
pub fn bump(_c: Counter, _n: u64) {}

#[cfg(feature = "profile")]
pub fn snapshot() -> Snapshot {
    let mut values = [0u64; Counter::ALL.len()];
    COUNTERS.with(|cs| {
        for (i, &c) in Counter::ALL.iter().enumerate() {
            values[i] = cs.cell(c).get();
        }
    });
    Snapshot { values }
}

#[cfg(not(feature = "profile"))]
pub fn snapshot() -> Snapshot {
    Snapshot {}
}

#[cfg(feature = "profile")]
#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    values: [u64; Counter::ALL.len()],
}

#[cfg(feature = "profile")]
impl Snapshot {
    pub fn get(&self, c: Counter) -> u64 {
        let idx = Counter::ALL.iter().position(|x| *x == c).unwrap();
        self.values[idx]
    }

    /// `later.delta(&earlier)` returns `later - earlier`, per counter.
    pub fn delta(&self, earlier: &Snapshot) -> Delta {
        let mut values = [0u64; Counter::ALL.len()];
        for (i, slot) in values.iter_mut().enumerate() {
            *slot = self.values[i].saturating_sub(earlier.values[i]);
        }
        Delta { values }
    }
}

#[cfg(not(feature = "profile"))]
#[derive(Clone, Copy, Debug)]
pub struct Snapshot {}

#[cfg(not(feature = "profile"))]
impl Snapshot {
    pub fn get(&self, _c: Counter) -> u64 {
        0
    }
    pub fn delta(&self, _earlier: &Snapshot) -> Delta {
        Delta {}
    }
}

#[cfg(feature = "profile")]
#[derive(Clone, Copy, Debug)]
pub struct Delta {
    values: [u64; Counter::ALL.len()],
}

#[cfg(feature = "profile")]
impl Delta {
    pub fn get(&self, c: Counter) -> u64 {
        let idx = Counter::ALL.iter().position(|x| *x == c).unwrap();
        self.values[idx]
    }

    /// Iterate over `(Counter, delta)` pairs whose delta is non-zero.
    pub fn iter_nonzero(&self) -> impl Iterator<Item = (Counter, u64)> + '_ {
        Counter::ALL
            .iter()
            .zip(self.values.iter())
            .filter_map(|(c, v)| if *v > 0 { Some((*c, *v)) } else { None })
    }
}

#[cfg(not(feature = "profile"))]
#[derive(Clone, Copy, Debug)]
pub struct Delta {}

#[cfg(not(feature = "profile"))]
impl Delta {
    pub fn get(&self, _c: Counter) -> u64 {
        0
    }
    pub fn iter_nonzero(&self) -> std::iter::Empty<(Counter, u64)> {
        std::iter::empty()
    }
}

#[macro_export]
macro_rules! count_ops {
    ($counter:ident) => {
        $crate::profile::counters::bump($crate::profile::counters::Counter::$counter, 1);
    };
    ($counter:ident, $n:expr) => {
        $crate::profile::counters::bump($crate::profile::counters::Counter::$counter, $n);
    };
}
