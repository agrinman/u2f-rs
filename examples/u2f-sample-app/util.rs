use sodiumoxide::crypto::secretbox;
use std::borrow::Borrow;

lazy_static! {
    static ref COOKIE_KEY: secretbox::Key = { secretbox::gen_key() };
}

pub fn seal(data: &[u8]) -> String {
    let nonce = secretbox::gen_nonce();
    let ctxt = secretbox::seal(data, &nonce, &COOKIE_KEY);
    let out = vec![nonce.0.borrow(), ctxt.as_slice()].concat();
    base64::encode_config(&out, base64::URL_SAFE_NO_PAD)
}

pub fn unseal(data: &str) -> std::result::Result<Vec<u8>, failure::Error> {
    let out = base64::decode_config(data.as_bytes(), base64::URL_SAFE_NO_PAD)?;

    if out.len() < secretbox::NONCEBYTES {
        return Err(failure::err_msg("invalid cookie"));
    }

    let nonce = secretbox::Nonce::from_slice(&out[..secretbox::NONCEBYTES]).unwrap();
    let ctxt = &out[secretbox::NONCEBYTES..];
    let message = secretbox::open(ctxt, &nonce, &COOKIE_KEY).map_err(|_| failure::err_msg("decrypt failed"))?;
    Ok(message)
}