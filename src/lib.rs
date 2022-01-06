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
