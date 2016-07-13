#![feature(test)]

extern crate chaskey;
extern crate rand;
extern crate test;

use chaskey::{Digester, Chaskey};
use rand::{Rng, ThreadRng, thread_rng};
use std::hash::{SipHasher, Hasher};
use test::{black_box, Bencher};


const SIZE: usize = 57;

#[bench]
fn sip_hasher(b: &mut Bencher) {
    let mut rng: ThreadRng = thread_rng();
    let (k0, k1) = rng.gen();
    let mut hasher = SipHasher::new_with_keys(k0, k1);
    bench_hasher(b, &mut hasher, SIZE);
}

#[bench]
fn chaskey_hasher(b: &mut Bencher) {
    let mut rng: ThreadRng = thread_rng();
    let key: [u32; 4] = rng.gen();
    let mut hasher: Digester<Chaskey> = Digester::new(key);
    bench_hasher(b, &mut hasher, SIZE);
}

fn bench_hasher<H: Hasher>(b: &mut Bencher, hasher: &mut H, size: usize) {
    let data: Vec<u8> = {
        let mut r = vec![0; size];
        let mut rng: ThreadRng = thread_rng();
        rng.fill_bytes(&mut r);
        r
    };

    b.iter(|| {
        hasher.write(&data);
        let r = hasher.finish();
    });
}

