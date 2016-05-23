//! The Chaskey block cipher.  
//!
//! The Chaskey MAC is, conceptually, constructed from this cipher,
//! and the security proofs for the MAC appeal to the cipher's
//! properties.
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
    use byteorder::{ByteOrder, LittleEndian};
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

    /// Test a Chaskey-LTS (16 round) plaintext/ciphertext/key triple,
    /// taken from FELIX.
    #[test]
    fn chaskey_lts_vectors() {
        const PLAINTEXT: [u8; 16] = [
            0xb8, 0x23, 0x28, 0x26,
            0xfd, 0x5e, 0x40, 0x5e,
            0x69, 0xa3, 0x01, 0xa9,
            0x78, 0xea, 0x7a, 0xd8
        ];
        
        const CIPHERTEXT: [u8; 16] = [
	    0xd5, 0x60, 0x8d, 0x4d, 
	    0xa2, 0xbf, 0x34, 0x7b,
	    0xab, 0xf8, 0x77, 0x2f, 
	    0xdf, 0xed, 0xde, 0x07
        ];
        
        const KEY: [u8; 16] = [
            0x56, 0x09, 0xe9, 0x68,
            0x5f, 0x58, 0xe3, 0x29,
            0x40, 0xec, 0xec, 0x98,
            0xc5, 0x22, 0x98, 0x2f
        ];

        let key: [u32; 4] = to_u32x4(&KEY);
        let plaintext: [u32; 4] = to_u32x4(&PLAINTEXT);
        let ciphertext: [u32; 4] = to_u32x4(&CIPHERTEXT);

        let mut buf = plaintext;
        encrypt::<ChaskeyLTS>(&mut buf, &key);
        assert_eq!(&buf, &ciphertext);

        decrypt::<ChaskeyLTS>(&mut buf, &key);
        assert_eq!(&buf, &plaintext);
    }

    fn to_u32x4(bytes: &[u8; 16]) -> [u32; 4] {
        [LittleEndian::read_u32(&bytes[0..4]),
         LittleEndian::read_u32(&bytes[4..8]),
         LittleEndian::read_u32(&bytes[8..12]),
         LittleEndian::read_u32(&bytes[12..16])]
    }
}
