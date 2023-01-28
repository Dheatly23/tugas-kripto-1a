pub mod playfair;
pub mod vigenere;

use std::marker::PhantomData;
use std::mem;
use std::{fmt, ptr, slice};

pub use playfair::*;
pub use vigenere::*;

pub struct CipherError(PhantomData<()>);

impl CipherError {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cipher error!")
    }
}

impl fmt::Debug for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Display>::fmt(&self, f)
    }
}

pub trait Encryptor {
    fn encrypt_byte(&mut self, byte: u8) -> Result<&[u8], CipherError>;
    fn encrypt_finish(&mut self) -> Result<Vec<u8>, CipherError>;

    fn chain<C>(self, other: C) -> Chain<Self, C>
    where
        Self: Sized,
        C: Encryptor,
    {
        Chain {
            child_1: self,
            child_2: other,
            temp: Vec::new(),
        }
    }

    fn invert(self) -> Invert<Self>
    where
        Self: Sized,
    {
        Invert(self)
    }

    fn map<F>(self, f: F) -> Map<Self, F>
    where
        Self: Sized,
        F: Fn(u8) -> u8,
    {
        Map { cipher: self, f }
    }

    fn filter<F>(self, f: F) -> Filter<Self, F>
    where
        Self: Sized,
        F: Fn(u8) -> bool,
    {
        Filter { cipher: self, f }
    }

    fn filter_map<F>(self, f: F) -> FilterMap<Self, F>
    where
        Self: Sized,
        F: Fn(u8) -> Option<u8>,
    {
        FilterMap { cipher: self, f }
    }
}

pub trait Decryptor {
    fn decrypt_byte(&mut self, byte: u8) -> Result<&[u8], CipherError>;
    fn decrypt_finish(&mut self) -> Result<Vec<u8>, CipherError>;

    fn chain<D>(self, other: D) -> Chain<Self, D>
    where
        Self: Sized,
        D: Decryptor,
    {
        Chain {
            child_1: self,
            child_2: other,
            temp: Vec::new(),
        }
    }

    fn invert(self) -> Invert<Self>
    where
        Self: Sized,
    {
        Invert(self)
    }

    fn map<F>(self, f: F) -> Map<Self, F>
    where
        Self: Sized,
        F: Fn(u8) -> u8,
    {
        Map { cipher: self, f }
    }

    fn filter<F>(self, f: F) -> Filter<Self, F>
    where
        Self: Sized,
        F: Fn(u8) -> bool,
    {
        Filter { cipher: self, f }
    }

    fn filter_map<F>(self, f: F) -> FilterMap<Self, F>
    where
        Self: Sized,
        F: Fn(u8) -> Option<u8>,
    {
        FilterMap { cipher: self, f }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Chain<C1, C2> {
    child_1: C1,
    child_2: C2,
    temp: Vec<u8>,
}

impl<C1: Encryptor, C2: Encryptor> Encryptor for Chain<C1, C2> {
    fn encrypt_byte(&mut self, byte: u8) -> Result<&[u8], CipherError> {
        self.temp.clear();
        for &byte in self.child_1.encrypt_byte(byte)? {
            match self.child_2.encrypt_byte(byte) {
                Ok(v) => self.temp.extend_from_slice(v),
                Err(e) => {
                    self.temp.clear();
                    return Err(e);
                }
            }
        }
        Ok(&self.temp)
    }

    fn encrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        self.temp.clear();
        for byte in self.child_1.encrypt_finish()? {
            self.temp
                .extend_from_slice(self.child_2.encrypt_byte(byte)?);
        }
        self.temp.extend(self.child_2.encrypt_finish()?);
        Ok(mem::replace(&mut self.temp, Vec::new()))
    }
}

impl<C1: Decryptor, C2: Decryptor> Decryptor for Chain<C1, C2> {
    fn decrypt_byte(&mut self, byte: u8) -> Result<&[u8], CipherError> {
        self.temp.clear();
        for &byte in self.child_1.decrypt_byte(byte)? {
            match self.child_2.decrypt_byte(byte) {
                Ok(v) => self.temp.extend_from_slice(v),
                Err(e) => {
                    self.temp.clear();
                    return Err(e);
                }
            }
        }
        Ok(&self.temp)
    }

    fn decrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        self.temp.clear();
        for byte in self.child_1.decrypt_finish()? {
            self.temp
                .extend_from_slice(self.child_2.decrypt_byte(byte)?);
        }
        self.temp.extend(self.child_2.decrypt_finish()?);
        Ok(mem::replace(&mut self.temp, Vec::new()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Invert<T>(T);

impl<T: Encryptor> Decryptor for Invert<T> {
    fn decrypt_byte(&mut self, byte: u8) -> Result<&[u8], CipherError> {
        self.0.encrypt_byte(byte)
    }

    fn decrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        self.0.encrypt_finish()
    }
}

impl<T: Decryptor> Encryptor for Invert<T> {
    fn encrypt_byte(&mut self, byte: u8) -> Result<&[u8], CipherError> {
        self.0.decrypt_byte(byte)
    }

    fn encrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        self.0.decrypt_finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Map<C, F> {
    cipher: C,
    f: F,
}

impl<C: Encryptor, F: FnMut(u8) -> u8> Encryptor for Map<C, F> {
    fn encrypt_byte(&mut self, byte: u8) -> Result<&[u8], CipherError> {
        let f = &mut self.f;
        self.cipher.encrypt_byte(f(byte))
    }

    fn encrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        self.cipher.encrypt_finish()
    }
}

impl<C: Decryptor, F: FnMut(u8) -> u8> Decryptor for Map<C, F> {
    fn decrypt_byte(&mut self, byte: u8) -> Result<&[u8], CipherError> {
        let f = &mut self.f;
        self.cipher.decrypt_byte(f(byte))
    }

    fn decrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        self.cipher.decrypt_finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Filter<C, F> {
    cipher: C,
    f: F,
}

impl<C: Encryptor, F: FnMut(u8) -> bool> Encryptor for Filter<C, F> {
    fn encrypt_byte(&mut self, byte: u8) -> Result<&[u8], CipherError> {
        let Self { cipher, f } = self;
        if f(byte) {
            cipher.encrypt_byte(byte)
        } else {
            Ok(empty_slice())
        }
    }

    fn encrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        self.cipher.encrypt_finish()
    }
}

impl<C: Decryptor, F: FnMut(u8) -> bool> Decryptor for Filter<C, F> {
    fn decrypt_byte(&mut self, byte: u8) -> Result<&[u8], CipherError> {
        let Self { cipher, f } = self;
        if f(byte) {
            cipher.decrypt_byte(byte)
        } else {
            Ok(empty_slice())
        }
    }

    fn decrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        self.cipher.decrypt_finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FilterMap<C, F> {
    cipher: C,
    f: F,
}

impl<C: Encryptor, F: FnMut(u8) -> Option<u8>> Encryptor for FilterMap<C, F> {
    fn encrypt_byte(&mut self, byte: u8) -> Result<&[u8], CipherError> {
        let Self { cipher, f } = self;
        match f(byte) {
            Some(b) => cipher.encrypt_byte(b),
            None => Ok(empty_slice()),
        }
    }

    fn encrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        self.cipher.encrypt_finish()
    }
}

impl<C: Decryptor, F: FnMut(u8) -> Option<u8>> Decryptor for FilterMap<C, F> {
    fn decrypt_byte(&mut self, byte: u8) -> Result<&[u8], CipherError> {
        let Self { cipher, f } = self;
        match f(byte) {
            Some(b) => cipher.decrypt_byte(b),
            None => Ok(empty_slice()),
        }
    }

    fn decrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        self.cipher.decrypt_finish()
    }
}

fn empty_slice<'a>() -> &'a [u8] {
    unsafe { slice::from_raw_parts(ptr::NonNull::dangling().as_ptr(), 0) }
}
