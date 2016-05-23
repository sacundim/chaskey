//! The block cipher variant of Chaskey.  **Experimental.**
//!
//! ## References
//!
//! * [Notes at the CryptoLux
//! website](https://www.cryptolux.org/index.php/Lightweight_Block_Ciphers#Chaskey_Cipher).

use core::*;

/// Encryption function for the Chaskey block cipher (8 rounds).
#[inline]
pub fn encrypt(msg: &mut [u32; 4], key: &[u32; 4]) {
    xor_u32x4(msg, key);
    permute8(msg);
    xor_u32x4(msg, key);
}

/// Decryption function for the Chaskey block cipher (8 rounds).
#[inline]
pub fn decrypt(msg: &mut [u32; 4], key: &[u32; 4]) {
    xor_u32x4(msg, key);
    invert8(msg);
    xor_u32x4(msg, key);
}


/// Encryption function for the Chaskey-12 block cipher (12 rounds).
#[inline]
pub fn encrypt12(msg: &mut [u32; 4], key: &[u32; 4]) {
    xor_u32x4(msg, key);
    permute12(msg);
    xor_u32x4(msg, key);
}

/// Decryption function for the Chaskey-12 block cipher (12 rounds).
#[inline]
pub fn decrypt12(msg: &mut [u32; 4], key: &[u32; 4]) {
    xor_u32x4(msg, key);
    invert12(msg);
    xor_u32x4(msg, key);
}


/// Encryption function for the Chaskey-LTS block cipher (16 rounds).
#[inline]
pub fn encrypt16(msg: &mut [u32; 4], key: &[u32; 4]) {
    xor_u32x4(msg, key);
    permute16(msg);
    xor_u32x4(msg, key);
}

/// Decryption function for the Chaskey-LTS block cipher (16 rounds).
#[inline]
pub fn decrypt16(msg: &mut [u32; 4], key: &[u32; 4]) {
    xor_u32x4(msg, key);
    invert16(msg);
    xor_u32x4(msg, key);
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
    fn encrypt_decrypt() {
        fn prop(msg: Block, key: Block) -> bool {
            let mut buf = msg;
            encrypt(&mut buf.0, &key.0);
            decrypt(&mut buf.0, &key.0);
            buf == msg
        }
        quickcheck(prop as fn(Block, Block) -> bool);
    }

    #[test]
    fn encrypt12_decrypt12() {
        fn prop(msg: Block, key: Block) -> bool {
            let mut buf = msg;
            encrypt12(&mut buf.0, &key.0);
            decrypt12(&mut buf.0, &key.0);
            buf == msg
        }
        quickcheck(prop as fn(Block, Block) -> bool);
    }

    #[test]
    fn encrypt16_decrypt16() {
        fn prop(msg: Block, key: Block) -> bool {
            let mut buf = msg;
            encrypt16(&mut buf.0, &key.0);
            decrypt16(&mut buf.0, &key.0);
            buf == msg
        }
        quickcheck(prop as fn(Block, Block) -> bool);
    }
}
