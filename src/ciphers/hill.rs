use std::mem;

use yew::AttrValue;

use crate::util::{MatrixU8, ModuloU8};

use super::{empty_slice, CipherError, Decryptor, Encryptor};

const A_UPPER: u8 = 'A' as _;
const Z_UPPER: u8 = 'Z' as _;
const A_LOWER: u8 = 'a' as _;
const Z_LOWER: u8 = 'z' as _;

const MODULO: u8 = Z_UPPER - A_UPPER + 1;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hill {
    mat: MatrixU8<MODULO>,
    mat_inv: MatrixU8<MODULO>,

    count: usize,
    temp: Vec<ModuloU8<MODULO>>,
}

impl Hill {
    pub fn new(mat: &[u8]) -> Result<Self, AttrValue> {
        let mut n = 1;
        loop {
            let (a, b) = (n * n, mat.len());
            if a > b {
                return Err("Matrix is not square!".into());
            } else if a == b {
                break;
            } else {
                n += 1;
            }
        }

        let mat = <MatrixU8<MODULO>>::new(
            n,
            mat.into_iter()
                .map(|v| <ModuloU8<MODULO>>::from(*v))
                .collect(),
        );
        let mat_inv = match mat.inverse() {
            Ok(v) => v,
            Err(e) => return Err(format!("{}", e).into()),
        };

        Ok(Self {
            mat,
            mat_inv,

            count: 0,
            temp: vec![0.into(); n * 2],
        })
    }
}

impl Encryptor for Hill {
    fn encrypt_byte(&mut self, mut byte: u8) -> Result<&[u8], CipherError> {
        byte = match byte {
            v @ A_UPPER..=Z_UPPER => v - A_UPPER,
            v @ A_LOWER..=Z_LOWER => v - A_LOWER,
            _ => return Err(CipherError::new()),
        };

        let size = self.mat.size();
        let count = self.count;
        self.count += 1;

        {
            let i = count % size;
            self.temp[i] = byte.into();
            if i != size - 1 {
                return Ok(empty_slice());
            }
        }

        let (a, b) = self.temp.split_at_mut(size);
        self.mat.slice_mult(a, &mut *b);

        // SAFETY: ModuloU8 is transparently represented by u8
        unsafe {
            let ret: &mut [u8] = mem::transmute(b);
            for i in ret.iter_mut() {
                *i += A_UPPER;
            }
            Ok(ret)
        }
    }

    fn encrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        let mut ret = Vec::new();
        let size = self.mat.size();
        while self.count % size != 0 {
            ret.extend_from_slice(self.encrypt_byte('A' as _)?);
        }

        Ok(ret)
    }
}

impl Decryptor for Hill {
    fn decrypt_byte(&mut self, mut byte: u8) -> Result<&[u8], CipherError> {
        byte = match byte {
            v @ A_UPPER..=Z_UPPER => v - A_UPPER,
            v @ A_LOWER..=Z_LOWER => v - A_LOWER,
            _ => return Err(CipherError::new()),
        };

        let size = self.mat.size();
        let count = self.count;
        self.count += 1;

        {
            let i = count % size;
            self.temp[i] = byte.into();
            if i != size - 1 {
                return Ok(empty_slice());
            }
        }

        let (a, b) = self.temp.split_at_mut(size);
        self.mat_inv.slice_mult(a, &mut *b);

        // SAFETY: ModuloU8 is transparently represented by u8
        unsafe {
            let ret: &mut [u8] = mem::transmute(b);
            for i in ret.iter_mut() {
                *i += A_UPPER;
            }
            Ok(ret)
        }
    }

    fn decrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        if self.count % self.mat.size() == 0 {
            Ok(Vec::new())
        } else {
            Err(CipherError::new())
        }
    }
}
