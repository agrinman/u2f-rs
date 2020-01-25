use bytes::{Bytes, BufMut};
use openssl::sha::sha256;
use byteorder::{ByteOrder, BigEndian};

use crate::util::*;
use crate::messages::RegisteredKey;
use crate::u2ferror::U2fError;
use std::convert::TryFrom;

/// The `Result` type used in this crate.
type Result<T> = ::std::result::Result<T, U2fError>;

// Single enrolment or pairing between an application and a token.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    pub key_handle: Vec<u8>,
    pub pub_key: Vec<u8>,

    // AttestationCert can be null for Authenticate requests.
    pub attestation_cert: Option<Vec<u8>>,
}

impl Registration {
    pub fn subject(&self) -> Option<String> {
        let cert = match self.attestation_cert.as_ref() {
            Some(cert) => cert,
            None => return None,
        };

        super::crypto::X509PublicKey::try_from(cert.as_slice()).map(|cert|{
            cert.subject_name()
        }).unwrap_or(None)
    }

    pub fn issuer(&self) -> Option<String> {
        let cert = match self.attestation_cert.as_ref() {
            Some(cert) => cert,
            None => return None,
        };

        super::crypto::X509PublicKey::try_from(cert.as_slice()).map(|cert|{
            cert.issuer_name()
        }).unwrap_or(None)
    }
}

pub fn parse_registration(app_id: String, client_data: Vec<u8>, registration_data: Vec<u8>) -> Result<Registration> {
    let reserved_byte = registration_data[0];
    if reserved_byte != 0x05 {
        return Err(U2fError::InvalidReservedByte);
    }

    let mut mem = Bytes::from(registration_data);
    
    //Start parsing ... advance the reserved byte.
    let _ = mem.split_to(1);

    // P-256 NIST elliptic curve
    let public_key = mem.split_to(65);

    // Key Handle
    let key_handle_size = mem.split_to(1);
    let key_len = BigEndian::read_uint(&key_handle_size[..], 1);
    let key_handle = mem.split_to(key_len as usize);

    // The certificate length needs to be inferred by parsing.
    let cert_len = asn_length(mem.clone()).unwrap();
    let attestation_certificate = mem.split_to(cert_len);

    // Remaining data corresponds to the signature 
    let signature = mem;

    // Let's build the msg to verify the signature
    let app_id_hash = sha256(&app_id.into_bytes());
    let client_data_hash = sha256(&client_data[..]);

    let mut msg = vec![0x00]; // A byte reserved for future use [1 byte] with the value 0x00
    msg.put(app_id_hash.as_ref());
    msg.put(client_data_hash.as_ref());
    msg.put(key_handle.clone()); 
    msg.put(public_key.clone()); 


    // The signature is to be verified by the relying party using the public key certified
    // in the attestation certificate.
    let cerificate_public_key = super::crypto::X509PublicKey::try_from(&attestation_certificate[..])?;

    if !(cerificate_public_key.is_secp256r1()?) {
        return Err(U2fError::BadCertificate);
    }

    let verified = cerificate_public_key.verify_signature(&signature[..], &msg[..])?;

    if !verified {
        return Err(U2fError::BadCertificate);
    }

    let registration = Registration {
        key_handle: key_handle[..].to_vec(),
        pub_key: public_key[..].to_vec(), 
        attestation_cert: Some(attestation_certificate[..].to_vec()),
    };

    Ok(registration)
}

pub fn get_registered_key(app_id: String, key_handle: Vec<u8>) -> RegisteredKey {
    RegisteredKey {
        app_id: app_id,
        version: U2F_V2.into(),
        key_handle: Some(get_encoded(key_handle.as_slice()))
    }
}