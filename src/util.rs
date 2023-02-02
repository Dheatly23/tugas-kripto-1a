use std::fmt;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

use num_integer::Integer;

pub struct CoprimeError<T> {
    value: T,
    modulo: T,
    gcd: T,
}

impl<T: fmt::Debug> fmt::Debug for CoprimeError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} is not coprime to {:?} (GCD: {:?})",
            self.value, self.modulo, self.gcd
        )
    }
}

impl<T: fmt::Display> fmt::Display for CoprimeError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} is not coprime to {} (GCD: {})",
            self.value, self.modulo, self.gcd
        )
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ModuloU8<const M: u8>(u8);

impl<const M: u8> ModuloU8<M> {
    pub fn inverse(self) -> Result<Self, CoprimeError<u8>> {
        let r = (self.0 as i32).extended_gcd(&(M as i32));
        if r.gcd != 1 {
            Err(CoprimeError {
                value: self.0,
                modulo: M,
                gcd: r.gcd as _,
            })
        } else {
            Ok(Self(r.x.rem_euclid(M as _) as _))
        }
    }
}

impl<const M: u8> From<u8> for ModuloU8<M> {
    fn from(value: u8) -> Self {
        Self(value % M)
    }
}

impl<const M: u8> From<ModuloU8<M>> for u8 {
    fn from(value: ModuloU8<M>) -> Self {
        value.0
    }
}

impl<const M: u8> Add for ModuloU8<M> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self((self.0 as i32 + rhs.0 as i32).rem_euclid(M as _) as _)
    }
}

impl<const M: u8> AddAssign for ModuloU8<M> {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = (self.0 as i32 + rhs.0 as i32).rem_euclid(M as _) as _;
    }
}

impl<const M: u8> Sub for ModuloU8<M> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self((self.0 as i32 - rhs.0 as i32).rem_euclid(M as _) as _)
    }
}

impl<const M: u8> SubAssign for ModuloU8<M> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = (self.0 as i32 - rhs.0 as i32).rem_euclid(M as _) as _;
    }
}

impl<const M: u8> Mul for ModuloU8<M> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self((self.0 as i32 * rhs.0 as i32).rem_euclid(M as _) as _)
    }
}

impl<const M: u8> MulAssign for ModuloU8<M> {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = (self.0 as i32 * rhs.0 as i32).rem_euclid(M as _) as _;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MatrixU8<const M: u8> {
    size: usize,
    arr: Vec<ModuloU8<M>>,
}

impl<const M: u8> MatrixU8<M> {
    #[inline]
    pub fn new(size: usize, arr: Vec<ModuloU8<M>>) -> Self {
        assert_eq!(size * size, arr.len());
        Self { size, arr }
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    pub fn inverse(&self) -> Result<Self, MatrixInversionError<u8>> {
        let Self { size: n, arr } = self;
        let n = *n;

        let mut a = arr.clone();
        let mut p: Vec<_> = (0..n).collect();

        for i in 0..n {
            let mut max_a = 0.into();
            let mut imax = i;

            for k in 0..n {
                let temp = a[k * n + i];
                if temp > max_a {
                    (max_a, imax) = (temp, k);
                }
            }

            if u8::from(max_a) == 0 {
                return Err(MatrixInversionError::DegenerateError);
            }

            if imax != i {
                p.swap(i, imax);
                let i1 = i * n;
                let i2 = imax * n;
                for j in 0..n {
                    a.swap(i1 + j, i2 + j);
                }
            }

            for j in i + 1..n {
                let mut t = a[i * n + i].inverse()?;
                a[j * n + i] *= t;

                for k in i + 1..n {
                    t = a[j * n + i] * a[i * n + k];
                    a[j * n + k] -= t;
                }
            }
        }

        let mut ia = vec![<ModuloU8<M>>::from(0); n * n];

        for j in 0..n {
            for i in 0..n {
                ia[i * n + j] = <_>::from((p[i] == j) as u8);

                for k in 0..i {
                    let t = a[i * n + k] * ia[k * n + j];
                    ia[i * n + j] -= t;
                }
            }

            for i in (0..n).rev() {
                for k in i + 1..n {
                    let t = a[i * n + k] * ia[k * n + j];
                    ia[i * n + j] -= t;
                }

                ia[i * n + j] *= a[i * n + i].inverse()?;
            }
        }

        Ok(Self { arr: ia, size: n })
    }

    pub fn slice_mult(&self, in_: &[ModuloU8<M>], out: &mut [ModuloU8<M>]) {
        for i in 0..self.size {
            let p = &mut out[i];
            *p = 0.into();
            let i_ = i * self.size;

            for j in 0..self.size {
                *p += in_[j] * self.arr[i_ + j];
            }
        }
    }
}

pub enum MatrixInversionError<T> {
    CoprimeError(CoprimeError<T>),
    DegenerateError,
}

impl<T> From<CoprimeError<T>> for MatrixInversionError<T> {
    fn from(value: CoprimeError<T>) -> Self {
        Self::CoprimeError(value)
    }
}

impl<T: fmt::Debug> fmt::Debug for MatrixInversionError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CoprimeError(e) => e.fmt(f),
            Self::DegenerateError => write!(f, "Degenerate matrix"),
        }
    }
}

impl<T: fmt::Display> fmt::Display for MatrixInversionError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CoprimeError(e) => e.fmt(f),
            Self::DegenerateError => write!(f, "Degenerate matrix"),
        }
    }
}
