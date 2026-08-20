#![no_main]

use hasilan_protocol::{
    AttachmentCompleteRequest, AttachmentInitiateRequest, EncryptedObject, LoginRequest,
    OrganizationCreateRequest, PutObjectRequest, RegisterRequest, SyncResponse,
    WebauthnLoginFinishRequest,
};
use libfuzzer_sys::fuzz_target;
use serde_json::from_slice;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, json)) = data.split_first() else {
        return;
    };
    match selector % 9 {
        0 => drop(from_slice::<RegisterRequest>(json)),
        1 => drop(from_slice::<LoginRequest>(json)),
        2 => drop(from_slice::<PutObjectRequest>(json)),
        3 => drop(from_slice::<EncryptedObject>(json)),
        4 => drop(from_slice::<SyncResponse>(json)),
        5 => drop(from_slice::<AttachmentInitiateRequest>(json)),
        6 => drop(from_slice::<AttachmentCompleteRequest>(json)),
        7 => drop(from_slice::<OrganizationCreateRequest>(json)),
        _ => drop(from_slice::<WebauthnLoginFinishRequest>(json)),
    }
});

