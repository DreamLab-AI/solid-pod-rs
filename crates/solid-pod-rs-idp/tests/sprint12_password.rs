//! Sprint 12 parity: password length validation (row 173).
//!
//! Verifies that `MIN_PASSWORD_LENGTH` is 8 and that
//! `validate_password_length` rejects short passwords and accepts
//! passwords at or above the minimum.

use solid_pod_rs_idp::credentials::{validate_password_length, LoginError, MIN_PASSWORD_LENGTH};

#[test]
fn min_password_length_constant_equals_8() {
    assert_eq!(MIN_PASSWORD_LENGTH, 8, "MIN_PASSWORD_LENGTH must be 8");
}

#[test]
fn validate_password_length_rejects_7_chars() {
    let err = validate_password_length("1234567").unwrap_err();
    match err {
        LoginError::PasswordTooShort { min_length } => {
            assert_eq!(min_length, 8);
        }
        other => panic!("expected PasswordTooShort, got: {other:?}"),
    }
}

#[test]
fn validate_password_length_accepts_8_chars() {
    validate_password_length("12345678").unwrap();
}

#[test]
fn validate_password_length_accepts_longer() {
    validate_password_length("a_very_long_secure_password").unwrap();
}

#[test]
fn validate_password_length_rejects_empty() {
    let err = validate_password_length("").unwrap_err();
    match err {
        LoginError::PasswordTooShort { min_length } => {
            assert_eq!(min_length, 8);
        }
        other => panic!("expected PasswordTooShort, got: {other:?}"),
    }
}
