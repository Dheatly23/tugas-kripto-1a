use std::slice;

use super::{CipherError, Decryptor, Encryptor};

const A_UPPER: u8 = 'A' as _;
const Z_UPPER: u8 = 'Z' as _;
const A_LOWER: u8 = 'a' as _;
const Z_LOWER: u8 = 'z' as _;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Vignere {
    key: Vec<u8>,

    count: usize,
    temp: [u8; 2],
}

impl Vignere {
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: Vec::from_iter(key.iter().filter_map(|&b| match b {
                A_UPPER..=Z_UPPER => Some(b - A_UPPER),
                A_LOWER..=Z_LOWER => Some(b - A_LOWER),
                _ => None,
            })),

            count: 0,
            temp: <_>::default(),
        }
    }
}

impl Encryptor for Vignere {
    fn encrypt_byte(&mut self, mut byte: u8) -> Result<&[u8], CipherError> {
        byte = match byte {
            v @ A_UPPER..=Z_UPPER => v - A_UPPER,
            v @ A_LOWER..=Z_LOWER => v - A_LOWER,
            _ => return Err(CipherError::new()),
        };
        byte = ((byte + self.key[self.count % self.key.len()]) % 26) + A_UPPER;
        self.count += 1;

        self.temp[1] = byte;
        if self.count % (5 * 12) == 0 {
            self.temp[0] = '\n' as _;
            Ok(&self.temp)
        } else if self.count % 5 == 0 {
            self.temp[0] = ' ' as _;
            Ok(&self.temp)
        } else {
            Ok(&self.temp[1..])
        }
    }

    fn encrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        Ok(Vec::new())
    }
}

impl Decryptor for Vignere {
    fn decrypt_byte(&mut self, mut byte: u8) -> Result<&[u8], CipherError> {
        byte = match byte {
            v @ A_UPPER..=Z_UPPER => v - A_UPPER,
            v @ A_LOWER..=Z_LOWER => v - A_LOWER,
            _ => return Err(CipherError::new()),
        };
        byte = ((byte + 26 - self.key[self.count % self.key.len()]) % 26) + A_UPPER;
        self.count += 1;

        self.temp[0] = byte;
        Ok(&self.temp[..1])
    }

    fn decrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Vignere256 {
    key: Vec<u8>,

    offset: usize,
    temp: u8,
}

impl Vignere256 {
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: Vec::from(key),
            offset: 0,
            temp: 0,
        }
    }
}

impl Encryptor for Vignere256 {
    fn encrypt_byte(&mut self, byte: u8) -> Result<&[u8], CipherError> {
        self.temp = byte.wrapping_add(self.key[self.offset]);
        self.offset = (self.offset + 1) % self.key.len();

        Ok(slice::from_ref(&self.temp))
    }

    fn encrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        Ok(Vec::new())
    }
}

impl Decryptor for Vignere256 {
    fn decrypt_byte(&mut self, byte: u8) -> Result<&[u8], CipherError> {
        self.temp = byte.wrapping_sub(self.key[self.offset]);
        self.offset = (self.offset + 1) % self.key.len();

        Ok(slice::from_ref(&self.temp))
    }

    fn decrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        Ok(Vec::new())
    }
}
