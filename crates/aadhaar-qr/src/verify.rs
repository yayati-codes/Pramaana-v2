//! UIDAI signature verification: RSA-2048 / SHA-256, PKCS#1 v1.5.

use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::Sha256;

use crate::Error;

pub(crate) fn verify_signature(
    message: &[u8],
    signature: &[u8],
    uidai_pubkey: &RsaPublicKey,
) -> Result<(), Error> {
    let key = VerifyingKey::<Sha256>::new(uidai_pubkey.clone());
    let signature = Signature::try_from(signature).map_err(|_| Error::SignatureInvalid)?;
    key.verify(message, &signature)
        .map_err(|_| Error::SignatureInvalid)
}
