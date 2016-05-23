//! An implementation of the [Chaskey lightweight
//! MAC](http://mouha.be/chaskey/).
//!
//! While Chaskey is a cryptographic algorithm, **this implementation
//! has not been reviewed for security**.  Use at your own risk.
//!
//! ## References
//!
//! * Mouha, Nicky, Bart Mennik, Anthony Van Herrewege, Dai Watanabe,
//!   Bart Preneet and Ingrid Verbauwhede.  2014.  ["Chaskey: An
//!   Efficient MAC Algorithm for 32-bit
//!   Microcontrollers."](https://eprint.iacr.org/2014/386.pdf)
//!   Cryptology ePrint Archive, Report 2014/386.
//! * Mouha, Nicky.  2015.  ["Chaskey: a MAC Algorithm for
//!   Microcontrollers: Status Update and Proposal of
//!   Chaskey-12."](http://eprint.iacr.org/2015/1182.pdf)  

extern crate byteorder;

#[cfg(test)]
extern crate quickcheck;

pub mod cipher;
pub mod core;
pub mod mac;
mod util;
