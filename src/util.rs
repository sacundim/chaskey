//! Utility functions useful for implementing Chaskey.

use byteorder::{ByteOrder, LittleEndian};

/// XOR a `[u32; 4]` value into the Chaskey state.
#[inline(always)]
pub fn xor_u32x4(state: &mut [u32; 4], block: &[u32; 4]) {
    state[0] ^= block[0];
    state[1] ^= block[1];
    state[2] ^= block[2];
    state[3] ^= block[3];
}

/// XOR a `[u8; 16]` value into the Chaskey state.
#[inline(always)]
pub fn xor_u8x16(state: &mut [u32; 4], block: &[u8; 16]) {
    state[0] ^= LittleEndian::read_u32(&block[0..4]);
    state[1] ^= LittleEndian::read_u32(&block[4..8]);
    state[2] ^= LittleEndian::read_u32(&block[8..12]);
    state[3] ^= LittleEndian::read_u32(&block[12..16]);
}


