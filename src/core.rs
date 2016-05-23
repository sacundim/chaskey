//! Core functions used to implement Chaskey.

use byteorder::{ByteOrder, LittleEndian};


/// Function used in the Chaskey key schedule.
#[inline(always)]
pub fn times_two(key: [u32; 4]) -> [u32; 4] {
    const C: [u32; 2] = [0x00, 0x87];
    [key[0].wrapping_shl(1) ^ C[key[3].wrapping_shr(31) as usize],
     key[1].wrapping_shl(1) ^ key[0].wrapping_shr(31),
     key[2].wrapping_shl(1) ^ key[1].wrapping_shr(31),
     key[3].wrapping_shl(1) ^ key[2].wrapping_shr(31)]
}


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


/// A common trait implemented by the various Chaskey permutations.
/// Chaskey processors in this library are parametrized by
/// implementations of this trait in order to select the Chaskey
/// variant in use.
pub trait Permutation {
    fn permute(state: &mut [u32; 4]);
    fn invert(state: &mut [u32; 4]);
}

// The original Chaskey permutation (8 rounds).
pub enum Chaskey {}

impl Permutation for Chaskey {
    #[inline(always)]
    fn permute(state: &mut [u32; 4]) {
        round(state); round(state); 
        round(state); round(state);
        round(state); round(state); 
        round(state); round(state);
    }

    #[inline(always)]
    fn invert(state: &mut [u32; 4]) {
        unround(state); unround(state); 
        unround(state); unround(state);
        unround(state); unround(state); 
        unround(state); unround(state);
    }
}


// The Chaskey-12 permutation (12 rounds).
pub enum Chaskey12 {}

impl Permutation for Chaskey12 {
    #[inline(always)]
    fn permute(state: &mut [u32; 4]) {
        round(state); round(state); 
        round(state); round(state);
        round(state); round(state); 

        round(state); round(state);
        round(state); round(state); 
        round(state); round(state);
    }

    #[inline(always)]
    fn invert(state: &mut [u32; 4]) {
        unround(state); unround(state); 
        unround(state); unround(state);
        unround(state); unround(state); 

        unround(state); unround(state);
        unround(state); unround(state); 
        unround(state); unround(state);
    }
}


// The Chaskey-LTS permutation (16 rounds).
pub enum ChaskeyLTS {}

impl Permutation for ChaskeyLTS {
    #[inline(always)]
    fn permute(state: &mut [u32; 4]) {
        round(state); round(state); 
        round(state); round(state);
        round(state); round(state); 
        round(state); round(state);

        round(state); round(state);
        round(state); round(state);
        round(state); round(state); 
        round(state); round(state);
    }

    #[inline(always)]
    fn invert(state: &mut [u32; 4]) {
        unround(state); unround(state); 
        unround(state); unround(state);
        unround(state); unround(state); 
        unround(state); unround(state);

        unround(state); unround(state); 
        unround(state); unround(state);
        unround(state); unround(state); 
        unround(state); unround(state);
    }
}

/// The Chaskey round function.
#[inline(always)]
pub fn round(v: &mut [u32; 4]) {
    v[0]  = v[0].wrapping_add(v[1]); v[2]  = v[2].wrapping_add(v[3]);
    v[1]  = v[1].rotate_left(5);     v[3]  = v[3].rotate_left(8);
    v[1] ^= v[0];                    v[3] ^= v[2];
    v[0]  = v[0].rotate_left(16);
    
    v[2]  = v[2].wrapping_add(v[1]); v[0]  = v[0].wrapping_add(v[3]);
    v[1]  = v[1].rotate_left(7);     v[3]  = v[3].rotate_left(13);
    v[1] ^= v[2];                    v[3] ^= v[0];
    v[2]  = v[2].rotate_left(16);    
}

/// The inverse of the Chaskey round function.
#[inline(always)]
pub fn unround(v: &mut [u32; 4]) {
    v[2]  = v[2].rotate_right(16);
    v[1] ^= v[2];                    v[3] ^= v[0];
    v[1]  = v[1].rotate_right(7);    v[3]  = v[3].rotate_right(13);
    v[2]  = v[2].wrapping_sub(v[1]); v[0]  = v[0].wrapping_sub(v[3]);

    v[0]  = v[0].rotate_right(16);
    v[1] ^= v[0];                    v[3] ^= v[2];
    v[1]  = v[1].rotate_right(5);    v[3]  = v[3].rotate_right(8);
    v[0]  = v[0].wrapping_sub(v[1]); v[2]  = v[2].wrapping_sub(v[3]);
}


#[cfg(test)]
mod tests {    
    use super::*;
    use quickcheck::{Arbitrary, Gen, quickcheck};

    #[derive(PartialEq, Eq, Clone, Copy, Debug)]
    struct Block([u32; 4]);

    impl Arbitrary for Block {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            Block([g.gen(), g.gen(), g.gen(), g.gen()])
        }
    }

    #[test]
    fn round_unround() {
        fn prop(msg: Block) -> bool {
            let mut buf = msg;
            round(&mut buf.0);
            unround(&mut buf.0);
            buf == msg
        }
        quickcheck(prop as fn(Block) -> bool);
    }

    #[test]
    fn permute8_invert8() {
        permute_invert::<Chaskey>()
    }

    #[test]
    fn permute12_invert12() {
        permute_invert::<Chaskey12>()
    }

    #[test]
    fn permute16_invert16() {
        permute_invert::<ChaskeyLTS>()
    }

    fn permute_invert<P: Permutation>() {
        fn prop<P: Permutation>(msg: Block) -> bool {
            let mut buf = msg;
            P::permute(&mut buf.0);
            P::invert(&mut buf.0);
            buf == msg
        }
        quickcheck(prop::<P> as fn(Block) -> bool);
    }

}
