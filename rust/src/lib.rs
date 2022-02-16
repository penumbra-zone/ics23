#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::large_enum_variant)]

extern crate alloc;
extern crate core;
#[cfg(not(feature = "std"))]
extern crate sp_std as std;

mod api;
mod compress;
mod helpers;
mod ics23;
mod ops;
mod verify;

pub mod tmp_jmt;

pub use crate::ics23::*;
pub use api::{
    iavl_spec, tendermint_spec, verify_batch_membership, verify_batch_non_membership,
    verify_membership, verify_non_membership,
};
pub use compress::{compress, decompress, is_compressed};
pub use helpers::{Hash, Result};
pub use verify::calculate_existence_root;
