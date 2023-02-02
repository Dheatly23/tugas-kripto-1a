use yew::AttrValue;

use crate::util::ModuloU8;

use super::{CipherError, Decryptor, Encryptor};

const A_UPPER: u8 = 'A' as _;
const Z_UPPER: u8 = 'Z' as _;
const A_LOWER: u8 = 'a' as _;
const Z_LOWER: u8 = 'z' as _;

const MODULO: u8 = Z_UPPER - A_UPPER + 1;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Affine {
    m: ModuloU8<MODULO>,
    n: ModuloU8<MODULO>,
    m_inv: ModuloU8<MODULO>,

    count: usize,
    temp: [u8; 2],
}

impl Affine {
    pub fn new(m: u8, n: u8) -> Result<Self, AttrValue> {
        if m == 0 {
            return Err(<_>::from("m is 0"));
        }
        let m = <ModuloU8<MODULO>>::from(m);
        let m_inv = match m.inverse() {
            Ok(v) => v,
            Err(e) => return Err(<_>::from(format!("{}", e))),
        };
        let n = <_>::from(n);

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
        byte = (self.m * byte.into() + self.n).into();
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
        byte = ((self.n - byte.into()) * self.m_inv).into();
        self.count += 1;

        self.temp[0] = byte + A_UPPER;
        Ok(&self.temp[..1])
    }

    fn decrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        Ok(Vec::new())
    }
}
