// copied from whir
// https://github.com/WizardOfMenlo/whir/tree/main
use std::ops::{Deref, DerefMut};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
// TODO (Gotti): Should pos rather be a u64? usize is platform-dependent, giving a platform-dependent limit on the number of variables.
// num_variables may be smaller as well.

// NOTE: Conversion BinaryHypercube <-> MultilinearPoint is Big Endian, using only the num_variables least significant bits of the number stored inside BinaryHypercube.

/// point on the binary hypercube {0,1}^n for some n.
///
/// The point is encoded via the n least significant bits of a usize in big endian order and we do not store n.
pub struct BinaryHypercubePoint(pub usize);

impl Deref for BinaryHypercubePoint {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for BinaryHypercubePoint {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// An iterator over all points of the binary hypercube `{0,1}^n`.
///
/// The hypercube consists of `2^num_variables` points, where `num_variables` represents
/// the number of binary dimensions.
///
/// - Each point is represented as an integer whose binary representation encodes its coordinates in
///   the hypercube.
/// - Iteration produces points in lexicographic order (`0, 1, 2, ...`).
#[derive(Debug)]
pub struct BinaryHypercube {
    /// Current position in the hypercube, encoded using the bits of `pos`.
    pos: usize,
    /// The number of dimensions (`n`) in the hypercube.
    num_variables: usize,
}

impl BinaryHypercube {
    /// Constructs a new iterator for a binary hypercube `{0,1}^num_variables`.
    pub const fn new(num_variables: usize) -> Self {
        // Note that we need strictly smaller, since some code would overflow otherwise.
        debug_assert!(num_variables < usize::BITS as usize);
        Self {
            pos: 0,
            num_variables,
        }
    }
}

impl Iterator for BinaryHypercube {
    type Item = BinaryHypercubePoint;

    /// Advances the iterator and returns the next point in the binary hypercube.
    ///
    /// The iteration stops once all `2^num_variables` points have been produced.
    fn next(&mut self) -> Option<Self::Item> {
        let curr = self.pos;
        if curr < (1 << self.num_variables) {
            self.pos += 1;
            Some(BinaryHypercubePoint(curr))
        } else {
            None
        }
    }
}
