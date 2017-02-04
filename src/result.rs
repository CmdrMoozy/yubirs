use chrono::datetime::DateTime;
use chrono::offset::utc::UTC;
use data_encoding::base64;
use error::Result;
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

lazy_static! {
    static ref STRING_TO_STATUS: HashMap<&'static str, Status> = {
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
    };
}

fn string_to_status(s: &str) -> Result<Status> {
    if let Some(status) = STRING_TO_STATUS.get(s) {
        return Ok(*status);
    } else {
        bail!("Invalid status '{}'", s);
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

lazy_static! {
    static ref STRING_TO_FIELD: HashMap<&'static str, Field> = {
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
    };
}

fn string_to_field(s: &str) -> Result<Field> {
    if let Some(field) = STRING_TO_FIELD.get(s) {
        return Ok(*field);
    } else {
        bail!("Invalid field name '{}'", s);
    }
}

fn split_response<'a>(response: &'a str) -> Result<HashMap<Field, &'a str>> {
    let mut m: HashMap<Field, &'a str> = HashMap::new();
    for line in response.lines() {
        if let Some(index) = line.find('=') {
            let (k, v) = line.split_at(index);
            m.insert(try!(string_to_field(k)), &v[1..]);
        }
    }
    Ok(m)
}

fn get_required_field<'a>(fields: &HashMap<Field, &'a str>, field: Field) -> Result<&'a str> {
    if let Some(s) = fields.get(&field) {
        return Ok(s);
    }
    bail!("Required field missing from response");
}

fn get_cloned_string_field(fields: &HashMap<Field, &str>, field: Field) -> Option<String> {
    fields.get(&field).map(|v| *v).map(|v| v.to_owned())
}

fn get_signature(fields: &HashMap<Field, &str>) -> Result<Vec<u8>> {
    Ok(try!(base64::decode(try!(get_required_field(fields, Field::Signature)).as_bytes())))
}

lazy_static! {
    static ref DATETIME_REGEX: Regex = Regex::new(
        r"^(?P<d>\d{4}-\d{2}-\d{2})T(?P<t>\d{2}:\d{2}:\d{2})Z(?P<ms>\d{4})$").unwrap();
}

fn get_timestamp(fields: &HashMap<Field, &str>) -> Result<DateTime<UTC>> {
    use chrono::TimeZone;
    if let Some(captures) =
        DATETIME_REGEX.captures(try!(get_required_field(fields, Field::Timestamp))) {
        let nanoseconds: u64 = try!(captures.name("ms").unwrap().as_str().parse());
        let reformatted = format!("{} {} {}",
                                  captures.name("d").unwrap().as_str(),
                                  captures.name("t").unwrap().as_str(),
                                  nanoseconds);
        return Ok(try!(UTC.datetime_from_str(reformatted.as_str(), "%Y-%m-%d %H:%M:%S %f")));
    }
    bail!("Response contained incorrectly formatted 't' field");
}

fn get_success_percent(fields: &HashMap<Field, &str>) -> Result<Option<u8>> {
    if let Some(sl) = fields.get(&Field::SuccessPercent) {
        let success_percent: u8 = try!(sl.parse());
        return Ok(Some(success_percent));
    }
    Ok(None)
}

#[derive(Clone, Debug)]
pub struct VerificationResult {
    pub otp: Option<String>,
    pub nonce: Option<String>,
    pub signature: Vec<u8>,
    pub timestamp: DateTime<UTC>,
    pub status: Status,
    pub decrypted_timestamp: Option<String>,
    pub decrypted_use_counter: Option<String>,
    pub decrypted_session_use_counter: Option<String>,
    pub success_percent: Option<u8>,
}

impl VerificationResult {
    pub fn new(response: Vec<u8>) -> Result<VerificationResult> {
        let response = try!(String::from_utf8(response));
        let fields = try!(split_response(response.as_str()));

        Ok(VerificationResult {
            otp: get_cloned_string_field(&fields, Field::Otp),
            nonce: get_cloned_string_field(&fields, Field::Nonce),
            signature: try!(get_signature(&fields)),
            timestamp: try!(get_timestamp(&fields)),
            status: try!(string_to_status(try!(get_required_field(&fields, Field::Status)))),
            decrypted_timestamp: get_cloned_string_field(&fields, Field::DecryptedTimestamp),
            decrypted_use_counter: get_cloned_string_field(&fields, Field::DecryptedUseCounter),
            decrypted_session_use_counter:
                get_cloned_string_field(&fields, Field::DecryptedSessionUseCounter),
            success_percent: try!(get_success_percent(&fields)),
        })
    }
}
