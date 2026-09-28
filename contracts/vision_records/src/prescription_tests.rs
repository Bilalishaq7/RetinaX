use crate::prescription::PrescriptionData;
use crate::validation;
use soroban_sdk::{Env, String};

#[test]
fn test_prescription_string_validation() {
    let env = Env::default();

    let valid_eye = PrescriptionData {
        sphere: String::from_str(&env, "-2.50"),
        cylinder: String::from_str(&env, "-1.25"),
        axis: String::from_str(&env, "180"),
        add: String::from_str(&env, "0.00"),
        pd: String::from_str(&env, "62"),
    };
    assert_eq!(validation::validate_prescription_data(&valid_eye), Ok(()));

    let invalid_eye = PrescriptionData {
        sphere: String::from_str(&env, "sphere_string_longer_than_sixteen_chars"),
        cylinder: String::from_str(&env, "-1.25"),
        axis: String::from_str(&env, "180"),
        add: String::from_str(&env, "0.00"),
        pd: String::from_str(&env, "62"),
    };
    assert!(validation::validate_prescription_data(&invalid_eye).is_err());
}
