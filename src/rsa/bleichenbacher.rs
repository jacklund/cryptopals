use super::*;
use std::ops::Mul;

pub struct PKCS15Oracle {
    private: PrivateKey,
}

impl PKCS15Oracle {
    pub fn new(private: &PrivateKey) -> Self {
        Self {
            private: private.clone(),
        }
    }

    pub fn check_padding(&self, ciphertext: &[u8]) -> bool {
        let plaintext = decrypt_without_padding(&self.private, ciphertext).unwrap();
        plaintext[0] == 0 && plaintext[1] == 2
    }
}

pub struct Bleichenbacher {
    oracle: PKCS15Oracle,
    c: BigUint,
    e: BigUint,
    n: BigUint,
    B: BigUint,
}

impl Bleichenbacher {
    pub fn new(private: &PrivateKey, public: &PublicKey, ciphertext: &[u8]) -> Self {
        Self {
            oracle: PKCS15Oracle::new(private),
            c: BigUint::from_bytes_be(ciphertext),
            e: public.exponent.clone(),
            n: private.modulus.clone(),
            B: BigUint::from(2u32).pow(8 * (public.byte_length() as u32 - 2)),
        }
    }

    fn check_pkcs_15(&self, s: &BigUint) -> bool {
        self.oracle.check_padding(
            &((&self.c * s.modpow(&self.e, &self.n)).mod_floor(&self.n)).to_bytes_be(),
        )
    }

    fn check_pkcs_15_and_increment_s(&self, mut s: BigUint) -> BigUint {
        while !self.check_pkcs_15(&s) {
            s += 1u8;
        }

        s
    }

    // We find an s >= n / 3B such that c * s ^ e mod n is conforming
    // This means that p * s is conforming, which means that
    // 2B <= p * s mod n < 3B
    fn step_2a(&self) -> BigUint {
        let s = self.n.div_ceil(&((&self.B).mul(3u8)));
        self.check_pkcs_15_and_increment_s(s)
    }

    fn step_2b(&self, s_prev: &BigUint) -> BigUint {
        let s = s_prev + 1u8;
        self.check_pkcs_15_and_increment_s(s)
    }

    fn step_2c(&self, s_prev: &BigUint, a: &BigUint, b: &BigUint) -> BigUint {
        let mut r = ((b * s_prev - &self.B * 2u8) * 2u8).div_ceil(&self.n);
        loop {
            let mut s = (2u8 * &self.B + &r * &self.n).div_ceil(b);
            while s <= (3u8 * &self.B + &r * &self.n).div_floor(a) {
                if self.check_pkcs_15(&s) {
                    return s;
                }
                s += 1u8;
            }
            r += 1u8;
        }
    }

    fn step_3(&self, m: &Vec<(BigUint, BigUint)>, s: &BigUint) -> Vec<(BigUint, BigUint)> {
        let mut new_m: Vec<(BigUint, BigUint)> = Vec::new();
        for (ref a, ref b) in m {
            let start = (a * s - &self.B * 3u8 + 1u8).div_ceil(&self.n);
            let end = (b * s - &self.B * 2u8).div_floor(&self.n);
            let mut r = start;
            while r <= end {
                let mut new_a = max(
                    a.clone(),
                    (((&self.B).mul(2u8)) + (&r * &self.n)).div_ceil(s),
                );
                let mut new_b = min(
                    b.clone(),
                    ((((&self.B).mul(3u8)) - 1u8) + (&r * &self.n)).div_floor(s),
                );
                let mut found = false;
                for interval in &new_m {
                    if !(interval.0 > new_b && interval.1 < new_a) {
                        new_a = min(interval.0.clone(), new_a);
                        new_b = max(interval.1.clone(), new_b);
                        new_m.push((new_a.clone(), new_b.clone()));
                        found = true;
                        break;
                    }
                }
                if !found {
                    new_m.push((new_a, new_b));
                }
                r += 1u8;
            }
        }
        new_m.sort();
        new_m.dedup();
        new_m
    }

    pub fn attack(&self) -> BigUint {
        let mut s = self.step_2a();

        let mut m = vec![(2u8 * &self.B, 3u8 * &self.B - 1u8)];
        m = self.step_3(&m, &s);

        let msg: BigUint;
        loop {
            match m.len() {
                l if l > 1 => s = self.step_2b(&s),
                l if l == 1 => {
                    if m[0].0 == m[0].1 {
                        msg = &m[0].0 % &self.n;
                        return msg;
                    }
                    s = self.step_2c(&s, &m[0].0, &m[0].1);
                }
                _ => unreachable!(),
            }

            m = self.step_3(&m, &s);
        }
    }
}
