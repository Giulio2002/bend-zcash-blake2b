//! `blake2b_simd::many` over this crate's `Params` and `State`.
//!
//! Same signatures as the original; the inputs are hashed one after another
//! (through Bend when it is on) instead of in SIMD lanes, so `degree()` only
//! reports the original implementation's lane count.

use crate::{Hash, Params, State};
use core::fmt;

/// The largest possible value of `degree()` on the target platform.
pub const MAX_DEGREE: usize = crate::reference::many::MAX_DEGREE;

/// The parallelism degree of the original implementation, detected at runtime.
pub fn degree() -> usize {
    crate::reference::many::degree()
}

/// Update any number of `State` objects at once.
pub fn update_many<'a, 'b, I, T>(pairs: I)
where
    I: IntoIterator<Item = (&'a mut State, &'b T)>,
    T: 'b + AsRef<[u8]> + ?Sized,
{
    for (state, input) in pairs {
        state.update(input.as_ref());
    }
}

/// A job for the [`hash_many`] function.
#[derive(Clone)]
pub struct HashManyJob<'a> {
    params: Params,
    input: &'a [u8],
    hash: Option<Hash>,
}

impl<'a> HashManyJob<'a> {
    /// Construct a new hashing job from a set of parameters and an input.
    #[inline]
    pub fn new(params: &Params, input: &'a [u8]) -> Self {
        HashManyJob { params: params.clone(), input, hash: None }
    }

    /// Get the hash from a finished job. Panics if `hash_many` has not run it.
    #[inline]
    pub fn to_hash(&self) -> Hash {
        self.hash.clone().expect("HashManyJob::to_hash before hash_many")
    }
}

impl<'a> fmt::Debug for HashManyJob<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HashManyJob {{ params: {:?}, input_len: {} }}", self.params, self.input.len())
    }
}

/// Hash any number of complete inputs all at once.
pub fn hash_many<'a, 'b, I>(hash_many_jobs: I)
where
    'b: 'a,
    I: IntoIterator<Item = &'a mut HashManyJob<'b>>,
{
    for job in hash_many_jobs {
        job.hash = Some(job.params.hash(job.input));
    }
}
