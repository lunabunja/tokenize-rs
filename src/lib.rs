/*
 * Copyright (c) 2022 Umut İnan Erdoğan
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 */

//! # Tokenize for Rust
//! 
//! Implementation of the [Tokenize] specification in rust
//! 
//! [Tokenize]: https://github.com/cyyynthia/tokenize

extern crate base64;
extern crate crypto;

use chrono::Utc;
use hmac_sha256::HMAC;
use std::{string::FromUtf8Error, str, error::Error};

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
        let signature_part = base64::encode_config(signature, base64::STANDARD_NO_PAD);

        Ok(format!("{}.{}", token, signature_part))
    }

    /// Validates a token.
    /// 
    /// # Arguments
    /// 
    /// * `token` - The provided token
    /// * `account_fetcher` - The closure used to fetch the account. It'll receive the account id as a string
    /// and should return a struct that implements [`Account`] wrapped in a [`Box`].
    /// 
    /// # Examples
    /// 
    /// ```
    /// use tokenize_rs::{Tokenize, Account};
    /// 
    /// pub struct TestAccount;
    /// 
    /// impl Account for TestAccount {
    ///     fn last_token_reset(&self) -> u64 {
    ///         0 // retrieve last token reset here
    ///     }
    /// }
    /// 
    /// let tokenize = Tokenize::new("uwu".as_bytes().to_vec());
    /// 
    /// tokenize.validate("MzI2MzU5NDY2MTcxODI2MTc2.OTUzMzQ4MDc.ucU3pXWOg2L6w5ErFLraknIOjzQLuI0HqhBDpdII+Wc", |_id| {
    ///     Some(Box::new(TestAccount))
    /// }).expect("Couldn't validate token");
    /// ```
    pub fn validate<S, F>(&self, token: S, account_fetcher: F) -> Result<Box<dyn Account>, Box<dyn Error>> where 
        S: Into<String>,
        F: Fn(String) -> Option<Box<dyn Account>> {
        let token = token.into();
        let splitted = token.split(".").collect::<Vec<&str>>();

        let max_len = if self.prefix.is_some() { 4 } else { 3 };
        if splitted.len() < 3 || splitted.len() > max_len { return Err("Token is invalid".into()); }

        let signature_string;

        if let Some(prefix) = &self.prefix {
            if prefix != splitted[0] {
                return Err("Token prefix doesn't match".into());
            }

            signature_string = format!("{}.{}.{}", prefix, splitted[1], splitted[2]);
        } else {
            signature_string = format!("{}.{}", splitted[0], splitted[1]);
        }

        let signature = Self::compute_hmac(&signature_string, &self.secret);

        if !crypto::util::fixed_time_eq(base64::encode_config(signature, base64::STANDARD_NO_PAD).as_bytes(), splitted[max_len - 1].as_bytes()) {
            return Err("Token signature doesn't match".into());
        }

        let account_id: String = str::from_utf8(&base64::decode_config(splitted[max_len - 3], base64::STANDARD_NO_PAD)?)?.to_string();
        let timestamp: u64 = str::from_utf8(&base64::decode_config(splitted[max_len - 2], base64::STANDARD_NO_PAD)?)?.parse()?;

        let account_opt = account_fetcher(account_id);
        
        let account = if let Some(account) = account_opt {
            account
        } else { return Err("No account is tied to this id".into()); };

        let last_token_reset = account.last_token_reset();
        if last_token_reset as i64 > ((timestamp as i64 * 1000) + TOKENIZE_EPOCH) {
            return Err("Token was invalidated".into());
        }

        Ok(account)
    }

    pub fn current_token_time() -> i64 {
        (Utc::now().timestamp_millis() - TOKENIZE_EPOCH) / 1000
    }

    fn compute_hmac(token: &str, secret: &Vec<u8>) -> [u8; 32] {
        let input = format!("TTF.{}.{}", TOKENIZE_VERSION, token);

        HMAC::mac(input.as_bytes(), secret)
    }
}

pub trait Account {
    fn last_token_reset(&self) -> u64;
}

#[cfg(test)]
mod tests {
    use crate::{Tokenize, Account};

    pub struct TestAccount {
        last_token_reset: u64
    }

    impl Account for TestAccount {
        fn last_token_reset(&self) -> u64 {
            self.last_token_reset
        }
    }

    #[test]
    fn generate_token() {
        let tokenize = Tokenize::new("uwu".as_bytes().to_vec());
        tokenize.generate("326359466171826176").expect("Couldn't generate new token");
    }

    #[test]
    fn generate_token_with_prefix() {
        let prefix = "prefix";

        let tokenize = Tokenize::new("uwu".as_bytes().to_vec()).set_prefix(prefix);
        assert!(tokenize.generate("326359466171826176").expect("Couldn't generate new token").starts_with(prefix));
    }

    #[test]
    fn validate_token() {
        let tokenize = Tokenize::new("uwu".as_bytes().to_vec());
        tokenize.validate("MzI2MzU5NDY2MTcxODI2MTc2.OTUzMzQ4MDc.ucU3pXWOg2L6w5ErFLraknIOjzQLuI0HqhBDpdII+Wc", |_id| {
            Some(Box::new(TestAccount { last_token_reset: 0 }))
        }).expect("Couldn't validate token");
    }

    #[test]
    fn validate_token_with_prefix() {
        let prefix = "prefix";

        let tokenize = Tokenize::new("uwu".as_bytes().to_vec()).set_prefix(prefix);
        tokenize.validate("prefix.MzI2MzU5NDY2MTcxODI2MTc2.OTUzNDE0NDE.JMOWr0OOZqbqqTkQp5LvvzBmsvu5JWbAPp4UpwzyJKI", |_id| {
            Some(Box::new(TestAccount { last_token_reset: 0 }))
        }).expect("Couldn't validate token");
    }

    #[test]
    fn validate_invalidated_token() {
        let tokenize = Tokenize::new("uwu".as_bytes().to_vec());
        assert!(tokenize.validate("MzI2MzU5NDY2MTcxODI2MTc2.OTUzMzQ4MDc.ucU3pXWOg2L6w5ErFLraknIOjzQLuI0HqhBDpdII+Wc", |_id| {
            Some(Box::new(TestAccount { last_token_reset: 1641641228500 }))
        }).is_err());
    }

    #[test]
    fn validate_token_with_invalid_signature() {
        let tokenize = Tokenize::new("uwu".as_bytes().to_vec());
        assert!(tokenize.validate("MzI2MzU5NDY2MTcxODI2MTc2.OTUzMzQ4MDc.thisisinvalid", |_id| {
            Some(Box::new(TestAccount { last_token_reset: 0 }))
        }).is_err());
    }
}
