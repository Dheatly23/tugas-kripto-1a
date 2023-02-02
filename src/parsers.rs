use nom::character::complete::{char as character, digit1, multispace0, multispace1};
use nom::combinator::{all_consuming, map_res, recognize};
use nom::multi::{many0_count, many1_count, separated_list1};
use nom::sequence::{delimited, terminated};
use nom::IResult;

pub fn unsigned_8(s: &str) -> IResult<&str, u8> {
    map_res(
        recognize(many1_count(terminated(digit1, many0_count(character('_'))))),
        |s| u8::from_str_radix(s, 10),
    )(s)
}

pub fn list_u8(s: &str) -> IResult<&str, Vec<u8>> {
    trimmed(separated_list1(multispace1, unsigned_8))(s)
}

pub fn trimmed<'a, O>(
    f: impl FnMut(&'a str) -> IResult<&'a str, O>,
) -> impl FnMut(&'a str) -> IResult<&'a str, O> {
    all_consuming(delimited(multispace0, f, multispace0))
}
