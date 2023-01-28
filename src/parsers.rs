use nom::character::complete::{char as character, digit1, multispace0, multispace1};
use nom::combinator::{all_consuming, map, map_res, recognize};
use nom::multi::{many0_count, many1_count};
use nom::sequence::{delimited, terminated, tuple};
use nom::IResult;

pub fn unsigned_8(s: &str) -> IResult<&str, u8> {
    map_res(
        recognize(many1_count(terminated(digit1, many0_count(character('_'))))),
        |s| u8::from_str_radix(s, 10),
    )(s)
}

pub fn mat3x3(s: &str) -> IResult<&str, [u8; 9]> {
    map(
        tuple((
            terminated(unsigned_8, multispace1),
            terminated(unsigned_8, multispace1),
            terminated(unsigned_8, multispace1),
            terminated(unsigned_8, multispace1),
            terminated(unsigned_8, multispace1),
            terminated(unsigned_8, multispace1),
            terminated(unsigned_8, multispace1),
            terminated(unsigned_8, multispace1),
            unsigned_8,
        )),
        |(a, b, c, d, e, f, g, h, i)| [a, b, c, d, e, f, g, h, i],
    )(s)
}

pub fn trimmed<'a, O>(
    f: impl FnMut(&'a str) -> IResult<&'a str, O>,
) -> impl FnMut(&'a str) -> IResult<&'a str, O> {
    all_consuming(delimited(multispace0, f, multispace0))
}
