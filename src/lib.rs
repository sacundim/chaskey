//! An implementation of the [Chaskey lightweight
//! MAC](http://mouha.be/chaskey/).
//!
//! While Chaskey is a cryptographic algorithm, **this implementation
//! has not been reviewed for security**.  Use at your own risk.

extern crate byteorder;

pub mod core;
pub mod mac;

