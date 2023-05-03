// Copyright 2017 Axel Rasmussen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::error::*;
use crate::otp::util;
use crate::otp::Otp;
use chrono::offset::Utc;
use chrono::DateTime;
use data_encoding;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

/// The response status codes validation servers might return.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Status {
    /// The OTP is valid.
    Ok,
    /// The OTP is in an invalid format.
    BadOtp,
    /// The OTP has already been seen by the service.
    ReplayedOtp,
    /// The HMAC signature verification failed.
    BadSignature,
    /// The request lacked a parameter.
    MissingParameter,
    /// The request ID doesn't exist.
    NoSuchClient,
    /// The request ID isn't allowed to verify OTPs.
    OperationNotAllowed,
    /// Internal server error in validation service.
    BackendError,
    /// Server could not get requested number of syncs before timeout.
    NotEnoughAnswers,
    /// Server has seen the OTP / nonce combination before.
    ReplayedRequest,
}

static STRING_TO_STATUS: Lazy<HashMap<&'static str, Status>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("OK", Status::Ok);
    m.insert("BAD_OTP", Status::BadOtp);
    m.insert("REPLAYED_OTP", Status::ReplayedOtp);
    m.insert("BAD_SIGNATURE", Status::BadSignature);
    m.insert("MISSING_PARAMETER", Status::MissingParameter);
    m.insert("NO_SUCH_CLIENT", Status::NoSuchClient);
    m.insert("OPERATION_NOT_ALLOWED", Status::OperationNotAllowed);
    m.insert("BACKEND_ERROR", Status::BackendError);
    m.insert("NOT_ENOUGH_ANSWERS", Status::NotEnoughAnswers);
    m.insert("REPLAYED_REQUEST", Status::ReplayedRequest);
    m
});

fn string_to_status(s: &str) -> Result<Status> {
    if let Some(status) = STRING_TO_STATUS.get(s) {
        return Ok(*status);
    } else {
        return Err(Error::InvalidArgument(format!("invalid status '{}'", s)));
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Field {
    /// The OTP, from the request.
    Otp,
    /// The nonce, from the request.
    Nonce,
    /// The HMAC signature.
    Signature,
    /// The timestamp.
    Timestamp,
    /// The request status.
    Status,
    /// The YubiKey internal timestamp.
    DecryptedTimestamp,
    /// The YubiKey internal usage counter.
    DecryptedUseCounter,
    /// The YubiKey internal session usage counter.
    DecryptedSessionUseCounter,
    /// The percent of external validation servers that replied successfully.
    SuccessPercent,
}

static STRING_TO_FIELD: Lazy<HashMap<&'static str, Field>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("otp", Field::Otp);
    m.insert("nonce", Field::Nonce);
    m.insert("h", Field::Signature);
    m.insert("t", Field::Timestamp);
    m.insert("status", Field::Status);
    m.insert("timestamp", Field::DecryptedTimestamp);
    m.insert("sessioncounter", Field::DecryptedUseCounter);
    m.insert("sessionuse", Field::DecryptedSessionUseCounter);
    m.insert("sl", Field::SuccessPercent);
    m
});

static FIELD_TO_STRING: Lazy<HashMap<Field, &'static str>> = Lazy::new(|| {
    STRING_TO_FIELD
        .iter()
        .map(|pair| (*pair.1, *pair.0))
        .collect()
});

fn string_to_field(s: &str) -> Result<Field> {
    if let Some(field) = STRING_TO_FIELD.get(s) {
        return Ok(*field);
    } else {
        return Err(Error::InvalidArgument(format!(
            "invalid field name '{}'",
            s
        )));
    }
}

fn split_response<'a>(response: &'a str) -> Result<HashMap<Field, &'a str>> {
    let mut m: HashMap<Field, &'a str> = HashMap::new();
    for line in response.lines() {
        if let Some(index) = line.find('=') {
            let (k, v) = line.split_at(index);
            m.insert(string_to_field(k)?, &v[1..]);
        }
    }
    Ok(m)
}

fn get_required_field<'a>(fields: &HashMap<Field, &'a str>, field: Field) -> Result<&'a str> {
    if let Some(s) = fields.get(&field) {
        return Ok(s);
    }
    return Err(Error::InvalidArgument(format!(
        "required field missing from response"
    )));
}

fn get_cloned_string_field(fields: &HashMap<Field, &str>, field: Field) -> Option<String> {
    fields.get(&field).map(|v| *v).map(|v| v.to_owned())
}

fn get_signature(fields: &HashMap<Field, &str>) -> Result<Vec<u8>> {
    Ok(data_encoding::BASE64.decode(get_required_field(fields, Field::Signature)?.as_bytes())?)
}

static DATETIME_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?P<d>\d{4}-\d{2}-\d{2})T(?P<t>\d{2}:\d{2}:\d{2})Z(?P<ms>\d{4})$").unwrap()
});

fn get_timestamp(fields: &HashMap<Field, &str>) -> Result<DateTime<Utc>> {
    use chrono::TimeZone;
    if let Some(captures) = DATETIME_REGEX.captures(get_required_field(fields, Field::Timestamp)?) {
        let nanoseconds: u64 = captures.name("ms").unwrap().as_str().parse()?;
        let reformatted = format!(
            "{} {} {}",
            captures.name("d").unwrap().as_str(),
            captures.name("t").unwrap().as_str(),
            nanoseconds
        );
        return Ok(Utc.datetime_from_str(reformatted.as_str(), "%Y-%m-%d %H:%M:%S %f")?);
    }
    return Err(Error::InvalidArgument(format!(
        "response contained incorrectly formatted 't' field"
    )));
}

fn get_success_percent(fields: &HashMap<Field, &str>) -> Result<Option<u8>> {
    if let Some(sl) = fields.get(&Field::SuccessPercent) {
        let success_percent: u8 = sl.parse()?;
        return Ok(Some(success_percent));
    }
    Ok(None)
}

fn get_signature_data(fields: &HashMap<Field, &str>) -> String {
    let mut pairs: Vec<(&str, &str)> = fields
        .iter()
        .filter(|pair| *pair.0 != Field::Signature)
        .map(|pair| (*FIELD_TO_STRING.get(&pair.0).unwrap(), *pair.1))
        .collect();
    pairs.sort_by_key(|v| v.0);
    let pairs: Vec<String> = pairs
        .into_iter()
        .map(|pair| format!("{}={}", pair.0, pair.1))
        .collect();
    pairs.join("&")
}

/// This structure provides type-safe access to all of the fields which may appear in a response /
/// verification result from the Yubico API. More details on what the fields mean are in the
/// official documentation:
/// https://developers.yubico.com/OTP/Specifications/OTP_validation_protocol.html.
#[derive(Clone, Debug)]
pub struct VerificationResult {
    pub otp: Option<String>,
    pub nonce: Option<String>,
    pub signature: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub status: Status,
    pub decrypted_timestamp: Option<String>,
    pub decrypted_use_counter: Option<String>,
    pub decrypted_session_use_counter: Option<String>,
    pub success_percent: Option<u8>,
    signature_data: String,
}

impl VerificationResult {
    /// Parse the given raw HTTP response into a result structure. Use the other pieces of
    /// information to verify that the response is valid (i.e., the contents and signature match
    /// what we expect).
    pub fn new(
        api_key: &[u8],
        expected_otp: &Otp,
        expected_nonce: &str,
        response: Vec<u8>,
    ) -> Result<VerificationResult> {
        let response = String::from_utf8(response)?;
        let fields = split_response(response.as_str())?;

        let result = VerificationResult {
            otp: get_cloned_string_field(&fields, Field::Otp),
            nonce: get_cloned_string_field(&fields, Field::Nonce),
            signature: get_signature(&fields)?,
            timestamp: get_timestamp(&fields)?,
            status: string_to_status(get_required_field(&fields, Field::Status)?)?,
            decrypted_timestamp: get_cloned_string_field(&fields, Field::DecryptedTimestamp),
            decrypted_use_counter: get_cloned_string_field(&fields, Field::DecryptedUseCounter),
            decrypted_session_use_counter: get_cloned_string_field(
                &fields,
                Field::DecryptedSessionUseCounter,
            ),
            success_percent: get_success_percent(&fields)?,
            signature_data: get_signature_data(&fields),
        };

        if result.status == Status::Ok {
            if result.otp.as_ref().map_or("", |s| s.as_str()) != expected_otp.to_string() {
                return Err(Error::Authentication(format!(
                    "OTP in response did not match OTP sent with request"
                )));
            }
        }
        if result.status == Status::Ok {
            if result.nonce.as_ref().map_or("", |s| s.as_str()) != expected_nonce {
                return Err(Error::Authentication(format!(
                    "nonce in response did not match nonce sent with request"
                )));
            }
        }

        if util::generate_signature(api_key, result.signature_data.clone())? != result.signature {
            return Err(Error::Authentication(format!(
                "verifying response signature failed"
            )));
        }

        Ok(result)
    }

    /// Returns true if and only if the result indicates that the OTP was successfully verified.
    pub fn is_valid(&self) -> bool {
        self.status == Status::Ok
    }

    /// Returns true if this error is retryable (i.e., the request may actually succeed if we try
    /// it again).
    pub fn is_retryable_error(&self) -> bool {
        self.status == Status::BackendError || self.status == Status::NotEnoughAnswers
    }
}
