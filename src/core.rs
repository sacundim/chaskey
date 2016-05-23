//! Core functions used to implement Chaskey.


/// Function used in the Chaskey key schedule.
#[inline]
pub fn times_two(key: [u32; 4]) -> [u32; 4] {
    const C: [u32; 2] = [0x00, 0x87];
    [key[0].wrapping_shl(1) ^ C[key[3].wrapping_shr(31) as usize],
     key[1].wrapping_shl(1) ^ key[0].wrapping_shr(31),
     key[2].wrapping_shl(1) ^ key[1].wrapping_shr(31),
     key[3].wrapping_shl(1) ^ key[2].wrapping_shr(31)]
}

#[inline(always)]
fn permute4(state: &mut [u32; 4]) {
    round(state); round(state); 
    round(state); round(state);
}

#[inline(always)]
pub fn permute8(state: &mut [u32; 4]) {
    permute4(state); permute4(state);
}

/// The Chaskey-12 permutation.
#[inline(always)]
pub fn permute12(state: &mut [u32; 4]) {
    permute4(state); permute8(state);
}

/// The Chaskey-LTS permutation.
#[inline(always)]
pub fn permute16(state: &mut [u32; 4]) {
    permute8(state); permute8(state);
}

/// The Chaskey round function.
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
