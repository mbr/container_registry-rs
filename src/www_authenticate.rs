use base64::Engine;
use nom::{
    bytes::complete::{tag_no_case, take_while, take_while1},
    character::is_space,
    combinator::map_res,
    IResult,
};

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct BasicAuthResponse {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
}

fn skip_whitespace(input: &[u8]) -> &[u8] {
    let (input, _) = take_while::<_, _, ()>(is_space)(input).expect("infallible");

    input
}

pub(crate) fn basic_auth_response(input: &[u8]) -> IResult<&[u8], BasicAuthResponse> {
    // Skip leading whitespace.
    let input = skip_whitespace(input);

    // Match tag.
    let (input, _) = tag_no_case("basic")(input)?;
    let input = skip_whitespace(input);

    // Get base64 data and decode.
    let (input, raw_data) = map_res(take_while1(|c: u8| !c.is_ascii_whitespace()), |raw_data| {
        base64::prelude::BASE64_STANDARD.decode(raw_data)
    })(input)?;

    let basic = match raw_data.iter().position(|&c| c == b':') {
        Some(idx) => BasicAuthResponse {
            username: raw_data[..idx].to_vec(),
            password: raw_data[(idx + 1)..].to_vec(),
        },
        None => BasicAuthResponse {
            username: raw_data.to_vec(),
            password: Vec::new(),
        },
    };

    Ok((input, basic))
}

#[cfg(test)]
mod tests {
    use crate::www_authenticate::{basic_auth_response, BasicAuthResponse};

    #[test]
    fn can_parse_known_response() {
        let input = b"Basic YWxhZGRpbjpvcGVuc2VzYW1l";

        assert_eq!(
            basic_auth_response(input),
            Ok((
                &b""[..],
                BasicAuthResponse {
                    username: b"aladdin".to_vec(),
                    password: b"opensesame".to_vec()
                }
            ))
        );

        let input = b"Basic c2FkZjpzZGZzZGZzZGZkc2Y=";
        assert_eq!(
            basic_auth_response(input),
            Ok((
                &b""[..],
                BasicAuthResponse {
                    username: b"sadf".to_vec(),
                    password: b"sdfsdfsdfdsf".to_vec()
                }
            ))
        );
    }
}
