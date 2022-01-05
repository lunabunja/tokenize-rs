extern crate base64;

use chrono::Utc;
use hmac_sha256::HMAC;
use std::string::FromUtf8Error;

pub const TOKENIZE_VERSION: u32 = 1;
pub const TOKENIZE_EPOCH: i64 = 1546300800000;

pub struct Tokenize {
    secret: Vec<u8>,
    prefix: Option<String>
}

impl Tokenize {
    pub fn new(secret: Vec<u8>) -> Tokenize {
        Tokenize {
            secret,
            prefix: None
        }
    }

    pub fn set_prefix<S: Into<String>>(mut self, prefix: S) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    pub fn generate<S: Into<String>>(&self, account_id: S) -> Result<String, FromUtf8Error> {
        let current_time = Self::current_token_time().to_string();
        let account_part = base64::encode_config(account_id.into(), base64::STANDARD_NO_PAD);
        let time_part = base64::encode_config(current_time, base64::STANDARD_NO_PAD);
        let prefix_part = if let Some(prefix) = self.prefix.as_ref() {
            format!("{}.", prefix)
        } else { String::new() };
        
        let token = format!("{}{}.{}", prefix_part, account_part, time_part);
        let signature = Self::compute_hmac(&token, &self.secret);

        Ok(format!("{}.{}", token, String::from_utf8(signature.to_vec())?))
    }

    pub fn current_token_time() -> i64 {
        (Utc::now().timestamp_millis() - TOKENIZE_EPOCH) / 1000
    }

    fn compute_hmac(token: &String, secret: &Vec<u8>) -> [u8; 32] {
        let input = format!("TTF.{}.{}", TOKENIZE_VERSION, token);

        HMAC::mac(input.as_bytes(), secret)
    }
}
