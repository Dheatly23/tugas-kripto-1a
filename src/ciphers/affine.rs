use num_integer::Integer;
use yew::AttrValue;

use super::{CipherError, Decryptor, Encryptor};

const A_UPPER: u8 = 'A' as _;
const Z_UPPER: u8 = 'Z' as _;
const A_LOWER: u8 = 'a' as _;
const Z_LOWER: u8 = 'z' as _;

const MODULO: u8 = Z_UPPER - A_UPPER + 1;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Affine {
    m: u8,
    n: u8,
    m_inv: u8,

    count: usize,
    temp: [u8; 2],
}

impl Affine {
    pub fn new(m: u8, n: u8) -> Result<Self, AttrValue> {
        if m == 0 {
            return Err(<_>::from("m is 0"));
        }
        let v = ((m % MODULO) as i8).extended_gcd(&(MODULO as i8));
        if v.gcd != 1 {
            return Err(<_>::from(format!(
                "{} has common factor {} with {}",
                m, v.gcd, MODULO
            )));
        }
        let m_inv = v.x.rem_euclid(MODULO as _) as u8;
        let n = n % MODULO;

        debug_assert_eq!((m as u32 * m_inv as u32) % MODULO as u32, 1);

        Ok(Self {
            m,
            n,
            m_inv,

            count: 0,
            temp: [0; 2],
        })
    }
}

impl Encryptor for Affine {
    fn encrypt_byte(&mut self, mut byte: u8) -> Result<&[u8], CipherError> {
        byte = match byte {
            v @ A_UPPER..=Z_UPPER => v - A_UPPER,
            v @ A_LOWER..=Z_LOWER => v - A_LOWER,
            _ => return Err(CipherError::new()),
        };
        byte = ((byte as i32 * self.m as i32) + self.n as i32).rem_euclid(MODULO as _) as u8;
        self.count += 1;

        self.temp[1] = byte + A_UPPER;

        let nl: u8 = if (self.count / 5) % 12 == 0 {
            '\n' as _
        } else {
            ' ' as _
        };
        match self.count % 5 {
            1 if self.count != 1 => {
                self.temp[0] = nl;
                Ok(&self.temp)
            }
            _ => Ok(&self.temp[1..]),
        }
    }

    fn encrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        Ok(Vec::new())
    }
}

impl Decryptor for Affine {
    fn decrypt_byte(&mut self, mut byte: u8) -> Result<&[u8], CipherError> {
        byte = match byte {
            v @ A_UPPER..=Z_UPPER => v - A_UPPER,
            v @ A_LOWER..=Z_LOWER => v - A_LOWER,
            _ => return Err(CipherError::new()),
        };
        byte = ((byte as i32 - self.n as i32) * self.m_inv as i32).rem_euclid(MODULO as _) as u8;
        self.count += 1;

        self.temp[0] = byte + A_UPPER;
        Ok(&self.temp[..1])
    }

    fn decrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        Ok(Vec::new())
    }
}
