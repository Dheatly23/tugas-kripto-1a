use std::mem;

use super::{empty_slice, CipherError, Decryptor, Encryptor};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Playfair {
    key: [u8; 25],
    key_inv: [u8; 25],

    count: usize,
    temp: [u8; 4],
}

fn byte_mapping(v: u8) -> Option<u8> {
    match v as _ {
        'A' | 'a' => Some(0),
        'B' | 'b' => Some(1),
        'C' | 'c' => Some(2),
        'D' | 'd' => Some(3),
        'E' | 'e' => Some(4),
        'F' | 'f' => Some(5),
        'G' | 'g' => Some(6),
        'H' | 'h' => Some(7),
        'I' | 'i' | 'J' | 'j' => Some(8),
        'K' | 'k' => Some(9),
        'L' | 'l' => Some(10),
        'M' | 'm' => Some(11),
        'N' | 'n' => Some(12),
        'O' | 'o' => Some(13),
        'P' | 'p' => Some(14),
        'Q' | 'q' => Some(15),
        'R' | 'r' => Some(16),
        'S' | 's' => Some(17),
        'T' | 't' => Some(18),
        'U' | 'u' => Some(19),
        'V' | 'v' => Some(20),
        'W' | 'w' => Some(21),
        'X' | 'x' => Some(22),
        'Y' | 'y' => Some(23),
        'Z' | 'z' => Some(24),
        _ => None,
    }
}

fn byte_unmapping(v: u8) -> u8 {
    match v {
        0 => 'A' as _,
        1 => 'B' as _,
        2 => 'C' as _,
        3 => 'D' as _,
        4 => 'E' as _,
        5 => 'F' as _,
        6 => 'G' as _,
        7 => 'H' as _,
        8 => 'I' as _,
        9 => 'K' as _,
        10 => 'L' as _,
        11 => 'M' as _,
        12 => 'N' as _,
        13 => 'O' as _,
        14 => 'P' as _,
        15 => 'Q' as _,
        16 => 'R' as _,
        17 => 'S' as _,
        18 => 'T' as _,
        19 => 'U' as _,
        20 => 'V' as _,
        21 => 'W' as _,
        22 => 'X' as _,
        23 => 'Y' as _,
        24 => 'Z' as _,
        _ => unreachable!(),
    }
}

impl Playfair {
    pub fn new(key: &[u8]) -> Result<Self, &'static str> {
        let mut ix = 0;
        let mut key_ = [0u8; 25];
        let mut key_inv = [0u8; 25];
        let mut mask = 0u32;

        for &k in key {
            let k = match byte_mapping(k) {
                Some(v) => v,
                None => continue,
            };

            let m = 1u32.wrapping_shl(k as _);
            if mask & m != 0 {
                continue;
            }
            mask |= m;

            debug_assert!(ix < 25);
            key_[ix] = k;
            key_inv[k as usize] = ix as _;
            ix += 1;
        }

        while ix < 25 {
            let k = mask.trailing_ones() as u8;

            let m = 1u32.wrapping_shl(k as _);
            debug_assert_eq!(mask & m, 0);
            mask |= m;

            key_[ix] = k;
            key_inv[k as usize] = ix as _;
            ix += 1;
        }

        Ok(Self {
            key: key_,
            key_inv,

            count: 0,
            temp: [0; 4],
        })
    }

    fn encrypt_pair(&self, mut a: u8, mut b: u8) -> (u8, u8) {
        a = self.key_inv[a as usize];
        b = self.key_inv[b as usize];

        let (mut da, mut ra) = (a / 5, a % 5);
        let (mut db, mut rb) = (b / 5, b % 5);

        if da == db {
            ra = (ra + 1) % 5;
            rb = (rb + 1) % 5;
        } else if ra == rb {
            da = (da + 1) % 5;
            db = (db + 1) % 5;
        } else {
            mem::swap(&mut ra, &mut rb);
        }

        a = da * 5 + ra;
        b = db * 5 + rb;

        a = self.key[a as usize];
        b = self.key[b as usize];

        (a, b)
    }

    fn decrypt_pair(&self, mut a: u8, mut b: u8) -> (u8, u8) {
        a = self.key_inv[a as usize];
        b = self.key_inv[b as usize];

        let (mut da, mut ra) = (a / 5, a % 5);
        let (mut db, mut rb) = (b / 5, b % 5);

        if da == db {
            ra = (ra + 4) % 5;
            rb = (rb + 4) % 5;
        } else if ra == rb {
            da = (da + 4) % 5;
            db = (db + 4) % 5;
        } else {
            mem::swap(&mut ra, &mut rb);
        }

        a = da * 5 + ra;
        b = db * 5 + rb;

        a = self.key[a as usize];
        b = self.key[b as usize];

        (a, b)
    }
}

impl Encryptor for Playfair {
    fn encrypt_byte(&mut self, mut byte: u8) -> Result<&[u8], CipherError> {
        byte = match byte_mapping(byte) {
            Some(v) => v,
            None => return Err(CipherError::new()),
        };

        let count = self.count;
        self.count += 1;
        if count % 2 == 0 {
            self.temp[0] = byte;

            return Ok(empty_slice());
        }

        let (mut a, mut b) = (self.temp[0], byte);
        if (a == b) & (b != 22) {
            b = 22;
            self.count += 1;
        }

        (a, b) = self.encrypt_pair(a, b);

        (self.temp[1], self.temp[2]) = (byte_unmapping(a), byte_unmapping(b));

        let nl: u8 = if (count / 5) % 12 == 0 {
            '\n' as _
        } else {
            ' ' as _
        };
        match count % 5 {
            0 if count != 0 => {
                self.temp[3] = self.temp[2];
                self.temp[2] = nl;
                Ok(&self.temp[1..])
            }
            1 if count != 1 => {
                self.temp[3] = self.temp[2];
                self.temp[2] = self.temp[1];
                self.temp[1] = nl;
                Ok(&self.temp[1..])
            }
            _ => Ok(&self.temp[1..3]),
        }
    }

    fn encrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        if self.count % 2 == 0 {
            Ok(Vec::new())
        } else {
            let ret = Ok(Vec::from(self.encrypt_byte('X' as _)?));
            debug_assert_eq!(self.count % 2, 0);
            ret
        }
    }
}

impl Decryptor for Playfair {
    fn decrypt_byte(&mut self, mut byte: u8) -> Result<&[u8], CipherError> {
        byte = match byte_mapping(byte) {
            Some(v) => v,
            None => return Err(CipherError::new()),
        };

        let count = self.count;
        self.count += 1;
        if count % 2 == 0 {
            self.temp[0] = byte;
            return Ok(empty_slice());
        }

        let (mut a, mut b) = (self.temp[0], byte);

        (a, b) = self.decrypt_pair(a, b);

        (self.temp[0], self.temp[1]) = (byte_unmapping(a), byte_unmapping(b));

        Ok(&self.temp[..2])
    }

    fn decrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        if self.count % 2 == 0 {
            Ok(Vec::new())
        } else {
            Err(CipherError::new())
        }
    }
}
