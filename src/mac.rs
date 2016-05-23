use core::*;
use std::hash::Hasher;

/// A Chaskey key schedule.
#[derive(Clone, Copy)]
pub struct Keys {
      key: [u32; 4],
       k1: [u32; 4],
       k2: [u32; 4]
}

/// Construct the Chaskey key schedule from the given key.
pub fn make_keys(key: [u32; 4]) -> Keys {
    let k1: [u32; 4] = times_two(key);
    let k2: [u32; 4] = times_two(k1);
    Keys {
        key: key,
         k1: k1,
         k2: k2
    }
}

/// A 128-bit Chaskey tag.
///
/// **WARNING:** This is a wrapper around an `[u32; 4]` in order to
/// provide constant-time equality comparisons.  You may unwrap it if
/// you like, but you need to be very careful what you do with, or
/// otherwise you may risk a [timing
/// attack](https://en.wikipedia.org/wiki/Timing_attack)!
#[derive(Eq, Debug)]
pub struct Tag([u32; 4]);

impl Tag {
    pub fn new(words: [u32; 4]) -> Tag { Tag(words) }

    /// Unwrap a `Tag` into its raw word array.  **Performing
    /// variable-time comparisons of these arrays may expose you to
    /// timing attacks**; stick to comparing the `Tag` wrappers if you
    /// can.
    pub fn raw_words(&self) -> &[u32; 4] {
        &self.0
    }

    pub fn to_u64(&self) -> u64 {
        (self.0[0] as u64) | (self.0[1] as u64).wrapping_shl(32)
    }

}

impl PartialEq for Tag {
    fn eq(&self, other: &Tag) -> bool {
        let mut result = true;
        result |= self.0[0] == other.0[0];
        result |= self.0[1] == other.0[1];
        result |= self.0[2] == other.0[2];
        result |= self.0[3] == other.0[3];
        result
    }
}


/// An incremental Chaskey digester.  This is a `Hasher` so you can
/// interact with it as you would do with one of them.  Additionally
/// you may use the `finish_128` method to get a full 128-bit tag.
#[derive(Clone)]
pub struct Chaskey {
     keys: Keys,
    state: [u32; 4],
      buf: [u8; 16],
        i: usize
}

impl Chaskey {
    /// Initialize a new Chaskey digester with the given key.
    pub fn new(key: [u32; 4]) -> Chaskey {
        let keys = make_keys(key);
        Chaskey {
             keys: keys,
            state: key,
              buf: [0u8; 16],
                i: 0
        }
    }

    /// Reset the digester to its initial state, so it is ready to
    /// authenticate a new message with the same key as when
    /// initialized.
    pub fn reset(&mut self) {
        self.state = self.keys.key;
        self.buf = [0u8; 16];
        self.i = 0;
    }

    /// Write data to the digester.
    pub fn write(&mut self, bytes: &[u8]) {
        for byte in bytes.iter() {
            if self.i % 16 == 0 && self.i != 0 {
                xor_u8x16(&mut self.state, &self.buf);
                permute8(&mut self.state);
            }
            self.buf[self.i % 16] = *byte;
            self.i += 1;
        }
    }
    
    pub fn finish_128(&self) -> Tag {
        let mut result = self.state;
        let buflen = self.i % 16;
        if buflen == 0 && self.i != 0 {
            xor_u8x16(&mut result, &self.buf);
            xor_u32x4(&mut result, &self.keys.k1);
            permute8(&mut result);
            xor_u32x4(&mut result, &self.keys.k1);
        } else {
            let mut last = [0u8; 16];
            for i in 0..buflen {
                last[i] = self.buf[i];
            }
            last[buflen] = 0x01;
            xor_u8x16(&mut result, &last);
            xor_u32x4(&mut result, &self.keys.k2);
            permute8(&mut result);
            xor_u32x4(&mut result, &self.keys.k2);
        }
        Tag(result)
    }

}

impl Hasher for Chaskey {
    fn write(&mut self, bytes: &[u8]) {
        Chaskey::write(self, bytes);
    }

    fn finish(&self) -> u64 {
        self.finish_128().to_u64()
    }
}

#[cfg(test)]
mod tests {
    use super::{Chaskey, Tag};

    #[test]
    fn test_incremental() {
        let mut hasher = Chaskey::new(KEY);
        let mut message: [u8; 64] = [0u8; 64];
        for i in 0..64 {
            message[i] = i as u8;
            let tag = {
                hasher.reset();
                hasher.write(&message[0..i]);
                hasher.finish_128()
            };
            println!("Iteration = {}", i);
            assert_eq!(tag, TEST_VECTORS[i]);
        }
    }

    const KEY: [u32; 4] = [0x833D3433, 0x009F389F, 0x2398E64F, 0x417ACF39];

    const TEST_VECTORS: [Tag; 64] = [
        Tag([0x792E8FE5, 0x75CE87AA, 0x2D1450B5, 0x1191970B]),
        Tag([0x13A9307B, 0x50E62C89, 0x4577BD88, 0xC0BBDC18]),
        Tag([0x55DF8922, 0x2C7FF577, 0x73809EF4, 0x4E5084C0]),
        Tag([0x1BDBB264, 0xA07680D8, 0x8E5B2AB8, 0x20660413]),
        Tag([0x30B2D171, 0xE38532FB, 0x16707C16, 0x73ED45F0]),
        Tag([0xBC983D0C, 0x31B14064, 0x234CD7A2, 0x0C92BBF9]),
        Tag([0x0DD0688A, 0xE131756C, 0x94C5E6DE, 0x84942131]),
        Tag([0x7F670454, 0xF25B03E0, 0x19D68362, 0x9F4D24D8]),
        Tag([0x09330F69, 0x62B5DCE0, 0xA4FBA462, 0xF20D3C12]),
        Tag([0x89B3B1BE, 0x95B97392, 0xF8444ABF, 0x755DADFE]),
        Tag([0xAC5B9DAE, 0x6CF8C0AC, 0x56E7B945, 0xD7ECF8F0]),
        Tag([0xD5B0DBEC, 0xC1692530, 0xD13B368A, 0xC0AE6A59]),
        Tag([0xFC2C3391, 0x285C8CD5, 0x456508EE, 0xC789E206]),
        Tag([0x29496F33, 0xAC62D558, 0xE0BAD605, 0xC5A538C6]),
        Tag([0xBF668497, 0x275217A1, 0x40C17AD4, 0x2ED877C0]),
        Tag([0x51B94DA4, 0xEFCC4DE8, 0x192412EA, 0xBBC170DD]),
        Tag([0x79271CA9, 0xD66A1C71, 0x81CA474E, 0x49831CAD]),
        Tag([0x048DA968, 0x4E25D096, 0x2D6CF897, 0xBC3959CA]),
        Tag([0x0C45D380, 0x2FD09996, 0x31F42F3B, 0x8F7FD0BF]),
        Tag([0xD8153472, 0x10C37B1E, 0xEEBDD61D, 0x7E3DB1EE]),
        Tag([0xFA4CA543, 0x0D75D71E, 0xAF61E0CC, 0x0D650C45]),
        Tag([0x808B1BCA, 0x7E034DE0, 0x6C8B597F, 0x3FACA725]),
        Tag([0xC7AFA441, 0x95A4EFED, 0xC9A9664E, 0xA2309431]),
        Tag([0x36200641, 0x2F8C1F4A, 0x27F6A5DE, 0x469D29F9]),
        Tag([0x37BA1E35, 0x43451A62, 0xE6865591, 0x19AF78EE]),
        Tag([0x86B4F697, 0x93A4F64F, 0xCBCBD086, 0xB476BB28]),
        Tag([0xBE7D2AFA, 0xAC513DE7, 0xFC599337, 0x5EA03E3A]),
        Tag([0xC56D7F54, 0x3E286A58, 0x79675A22, 0x099C7599]),
        Tag([0x3D0F08ED, 0xF32E3FDE, 0xBB8A1A8C, 0xC3A3FEC4]),
        Tag([0x2EC171F8, 0x33698309, 0x78EFD172, 0xD764B98C]),
        Tag([0x5CECEEAC, 0xA174084C, 0x95C3A400, 0x98BEE220]),
        Tag([0xBBDD0C2D, 0xFAB6FCD9, 0xDCCC080E, 0x9F04B41F]),
        Tag([0x60B3F7AF, 0x37EEE7C8, 0x836CFD98, 0x782CA060]),
        Tag([0xDF44EA33, 0xB0B2C398, 0x0583CE6F, 0x846D823E]),
        Tag([0xC7E31175, 0x6DB4E34D, 0xDAD60CA1, 0xE95ABA60]),
        Tag([0xE0DC6938, 0x84A0A7E3, 0xB7F695B5, 0xB46A010B]),
        Tag([0x1CEB6C66, 0x3535F274, 0x839DBC27, 0x80B4599C]),
        Tag([0xBBA106F4, 0xD49B697C, 0xB454B5D9, 0x2B69E58B]),
        Tag([0x5AD58A39, 0xDFD52844, 0x34973366, 0x8F467DDC]),
        Tag([0x67A67B1F, 0x3575ECB3, 0x1C71B19D, 0xA885C92B]),
        Tag([0xD5ABCC27, 0x9114EFF5, 0xA094340E, 0xA457374B]),
        Tag([0xB559DF49, 0xDEC9B2CF, 0x0F97FE2B, 0x5FA054D7]),
        Tag([0x2ACA7229, 0x99FF1B77, 0x156D66E0, 0xF7A55486]),
        Tag([0x565996FD, 0x8F988CEF, 0x27DC2CE2, 0x2F8AE186]),
        Tag([0xBE473747, 0x2590827B, 0xDC852399, 0x2DE46519]),
        Tag([0xF860AB7D, 0x00F48C88, 0x0ABFBB33, 0x91EA1838]),
        Tag([0xDE15C7E1, 0x1D90EFF8, 0xABC70129, 0xD9B2F0B4]),
        Tag([0xB3F0A2C3, 0x775539A7, 0x6CAA3BC1, 0xD5A6FC7E]),
        Tag([0x127C6E21, 0x6C07A459, 0xAD851388, 0x22E8BF5B]),
        Tag([0x08F3F132, 0x57B587E3, 0x087AD505, 0xFA070C27]),
        Tag([0xA826E824, 0x3F851E6A, 0x9D1F2276, 0x7962AD37]),
        Tag([0x14A6A13A, 0x469962FD, 0x914DB278, 0x3A9E8EC2]),
        Tag([0xFE20DDF7, 0x06505229, 0xF9C9F394, 0x4361A98D]),
        Tag([0x1DE7A33C, 0x37F81C96, 0xD9B967BE, 0xC00FA4FA]),
        Tag([0x5FD01E9A, 0x9F2E486D, 0x93205409, 0x814D7CC2]),
        Tag([0xE17F5CA5, 0x37D4BDD0, 0x1F408335, 0x43B6B603]),
        Tag([0x817CEEAE, 0x796C9EC0, 0x1BB3DED7, 0xBAC7263B]),
        Tag([0xB7827E63, 0x0988FEA0, 0x3800BD91, 0xCF876B00]),
        Tag([0xF0248D4B, 0xACA7BDC8, 0x739E30F3, 0xE0C469C2]),
        Tag([0x67363EB6, 0xFAE8E047, 0xF0C1C8E5, 0x828CCD47]),
        Tag([0x3DBD1D15, 0x05092D7B, 0x216FC6E3, 0x446860FB]),
        Tag([0xEBF39102, 0x8F4C1708, 0x519D2F36, 0xC67C5437]),
        Tag([0x89A0D454, 0x9201A282, 0xEA1B1E50, 0x1771BEDC]),
        Tag([0x9047FAD7, 0x88136D8C, 0xA488286B, 0x7FE9352C])
    ];
}

