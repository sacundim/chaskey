//! The Chaskey block cipher.  The Chaskey MAC is, conceptually,
//! constructed in terms of this cipher.
//!
//! ## Disclaimer
//!
//! **This code has not been reviewed for security.  Use at your own
//! risk.**
//!
//! ## References
//!
//! * [Notes at the CryptoLux
//! website](https://www.cryptolux.org/index.php/Lightweight_Block_Ciphers#Chaskey_Cipher).

pub use core::*;
use util::xor_u32x4;


/// Encryption function for the Chaskey block cipher, parametrized by
/// the permutation to use.
#[inline]
pub fn encrypt<P: Permutation>(msg: &mut [u32; 4], key: &[u32; 4]) {
    xor_u32x4(msg, key);
    P::permute(msg);
    xor_u32x4(msg, key);
}

/// Decryption function for the Chaskey block cipher, parametrized by
/// the permutation to use.
#[inline]
pub fn decrypt<P: Permutation>(msg: &mut [u32; 4], key: &[u32; 4]) {
    xor_u32x4(msg, key);
    P::invert(msg);
    xor_u32x4(msg, key);
}


#[cfg(test)]
mod tests {    
    use core::*;
    use super::{encrypt, decrypt};
    use quickcheck::{Arbitrary, Gen, quickcheck};

    #[derive(PartialEq, Eq, Clone, Copy, Debug)]
    struct Block([u32; 4]);

    impl Arbitrary for Block {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            Block([g.gen(), g.gen(), g.gen(), g.gen()])
        }
    }

    fn encrypt_decrypt<P: Permutation>() {
        fn prop<P: Permutation>(msg: Block, key: Block) -> bool {
            let mut buf = msg;
            encrypt::<P>(&mut buf.0, &key.0);
            decrypt::<P>(&mut buf.0, &key.0);
            buf == msg
        }
        quickcheck(prop::<P> as fn(Block, Block) -> bool);
    }

    #[test]
    fn encrypt8_decrypt8() {
        encrypt_decrypt::<Chaskey>();
    }

    #[test]
    fn encrypt12_decrypt12() {
        encrypt_decrypt::<Chaskey12>();
    }

    #[test]
    fn encrypt16_decrypt16() {
        encrypt_decrypt::<ChaskeyLTS>();
    }

}
