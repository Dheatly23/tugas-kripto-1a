use num_integer::Integer;
use yew::AttrValue;

use super::{empty_slice, CipherError, Decryptor, Encryptor};

const A_UPPER: u8 = 'A' as _;
const Z_UPPER: u8 = 'Z' as _;
const A_LOWER: u8 = 'a' as _;
const Z_LOWER: u8 = 'z' as _;

const MODULO: u8 = Z_UPPER - A_UPPER + 1;

fn matmul(m: &[[u8; 3]; 3], v: [u8; 3]) -> [u8; 3] {
    [
        (v[0] as u32 * m[0][0] as u32 + v[1] as u32 * m[1][0] as u32 + v[2] as u32 * m[2][0] as u32)
            .rem_euclid(MODULO as u32) as u8,
        (v[0] as u32 * m[0][1] as u32 + v[1] as u32 * m[1][1] as u32 + v[2] as u32 * m[2][1] as u32)
            .rem_euclid(MODULO as u32) as u8,
        (v[0] as u32 * m[0][2] as u32 + v[1] as u32 * m[1][2] as u32 + v[2] as u32 * m[2][2] as u32)
            .rem_euclid(MODULO as u32) as u8,
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hill {
    mat: [[u8; 3]; 3],
    mat_inv: [[u8; 3]; 3],

    count: usize,
    temp: [u8; 4],
}

impl Hill {
    pub fn new(mat: [u8; 9]) -> Result<Self, AttrValue> {
        const M: i32 = MODULO as _;
        let mat = [
            [
                mat[0].rem_euclid(MODULO),
                mat[1].rem_euclid(MODULO),
                mat[2].rem_euclid(MODULO),
            ],
            [
                mat[3].rem_euclid(MODULO),
                mat[4].rem_euclid(MODULO),
                mat[5].rem_euclid(MODULO),
            ],
            [
                mat[6].rem_euclid(MODULO),
                mat[7].rem_euclid(MODULO),
                mat[8].rem_euclid(MODULO),
            ],
        ];

        let a = mat[0][0] as i32;
        let b = mat[0][1] as i32;
        let c = mat[0][2] as i32;
        let d = mat[1][0] as i32;
        let e = mat[1][1] as i32;
        let f = mat[1][2] as i32;
        let g = mat[2][0] as i32;
        let h = mat[2][1] as i32;
        let i = mat[2][2] as i32;

        let det = [
            a * e * i,
            b * f * g,
            c * d * h,
            -(a * f * h),
            -(b * d * i),
            -(c * e * g),
        ]
        .into_iter()
        .fold(0, |a, b| (a + b).rem_euclid(M));
        if det == 0 {
            return Err(<_>::from("determinant is 0"));
        }

        let v = det.extended_gcd(&M);
        if v.gcd != 1 {
            return Err(<_>::from(format!(
                "determinant {} has common factor {} with {}",
                det, v.gcd, M
            )));
        }
        let det_inv = v.x.rem_euclid(M);

        #[inline]
        fn f_(det_inv: i32, a: i32, b: i32, c: i32, d: i32, inv: bool) -> i32 {
            let mut v = a * b - c * d;
            if inv {
                v = -v;
            }
            (v * det_inv).rem_euclid(M)
        }

        let mat_inv = [
            [
                f_(det_inv, e, i, f, h, false) as _,
                f_(det_inv, b, i, c, h, true) as _,
                f_(det_inv, b, f, c, e, false) as _,
            ],
            [
                f_(det_inv, d, i, f, g, true) as _,
                f_(det_inv, a, i, c, g, false) as _,
                f_(det_inv, a, f, c, d, true) as _,
            ],
            [
                f_(det_inv, d, h, e, g, false) as _,
                f_(det_inv, a, h, b, g, true) as _,
                f_(det_inv, a, e, b, d, false) as _,
            ],
        ];

        debug_assert_eq!(
            [
                matmul(&mat, mat_inv[0]),
                matmul(&mat, mat_inv[1]),
                matmul(&mat, mat_inv[2]),
            ],
            [[1, 0, 0], [0, 1, 0], [0, 0, 1]]
        );

        Ok(Self {
            mat,
            mat_inv,

            count: 0,
            temp: [0; 4],
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

        let count = self.count;
        self.count += 1;
        if let c @ (0 | 1) = count % 3 {
            self.temp[c] = byte;
            return Ok(empty_slice());
        }

        let [mut a, mut b, mut c] = matmul(&self.mat, [self.temp[0], self.temp[1], byte]);
        a += A_UPPER;
        b += A_UPPER;
        c += A_UPPER;

        let nl: u8 = if (count / 5) % 12 == 0 {
            '\n' as _
        } else {
            ' ' as _
        };
        match count % 5 {
            0 if count != 0 => {
                self.temp[0] = a;
                self.temp[1] = b;
                self.temp[2] = nl;
                self.temp[3] = c;
                Ok(&self.temp)
            }
            1 if count != 1 => {
                self.temp[0] = a;
                self.temp[1] = nl;
                self.temp[2] = b;
                self.temp[3] = c;
                Ok(&self.temp)
            }
            2 if count != 2 => {
                self.temp[0] = nl;
                self.temp[1] = a;
                self.temp[2] = b;
                self.temp[3] = c;
                Ok(&self.temp)
            }
            _ => {
                self.temp[0] = a;
                self.temp[1] = b;
                self.temp[2] = c;
                Ok(&self.temp[..3])
            }
        }
    }

    fn encrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        let mut ret = Vec::new();
        while self.count % 3 != 0 {
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

        let count = self.count;
        self.count += 1;
        if let c @ (0 | 1) = count % 3 {
            self.temp[c] = byte;
            return Ok(empty_slice());
        }

        let [a, b, c] = matmul(&self.mat_inv, [self.temp[0], self.temp[1], byte]);

        self.temp[0] = a + A_UPPER;
        self.temp[1] = b + A_UPPER;
        self.temp[2] = c + A_UPPER;
        Ok(&self.temp[..3])
    }

    fn decrypt_finish(&mut self) -> Result<Vec<u8>, CipherError> {
        if self.count % 3 == 0 {
            Ok(Vec::new())
        } else {
            Err(CipherError::new())
        }
    }
}
