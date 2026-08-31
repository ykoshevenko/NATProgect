// TODO: ECDH-сессии, ключи групп, шифрование ChaCha20-Poly1305, подписи Ed25519.
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

pub struct SessionKey {
    inner: [u8; KEY_LEN],
}

impl SessionKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner: [u8; KEY_LEN] =
            bytes.try_into().map_err(|_| Error::InvalidKey("session key".into()))?;
        Ok(Self { inner })
    }

    pub fn derive(
        our_secret: &StaticSecret,
        their_public: &PublicKey,
        salt: &[u8],
    ) -> Result<Self> {
        let shared = our_secret.diffie_hellman(their_public);
        let hk = Hkdf::<Sha256>::new(Some(salt), shared.as_bytes());
        let mut okm = [0u8; KEY_LEN];
        hk.expand(b"natprogect/v1/session", &mut okm)
            .map_err(|_| Error::InvalidKey("hkdf".into()))?;
        Ok(Self { inner: okm })
    }
}

impl AsRef<[u8]> for SessionKey {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

pub fn encrypt(
    key: &SessionKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let mut raw = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut raw);
    let nonce = Nonce::from_slice(&raw);
    let ct = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| Error::Encrypt)?;
    Ok((raw, ct))
}

pub fn decrypt(
    key: &SessionKey,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| Error::Auth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn pair() -> (StaticSecret, PublicKey) {
        let s = StaticSecret::random_from_rng(OsRng);
        let p = PublicKey::from(&s);
        (s, p)
    }

    #[test]
    fn ecdh_is_symmetric() {
        let (alice_s, alice_p) = pair();
        let (bob_s, bob_p) = pair();

        let k_a = SessionKey::derive(&alice_s, &bob_p, b"test-salt").unwrap();
        let k_b = SessionKey::derive(&bob_s, &alice_p, b"test-salt").unwrap();

        assert_eq!(k_a.as_ref(), k_b.as_ref());
    }

    #[test]
    fn roundtrip() {
        let (alice_s, _) = pair();
        let (_, bob_p) = pair();
        let key = SessionKey::derive(&alice_s, &bob_p, b"test-salt").unwrap();

        let msg = b"privet, p2p";
        let (nonce, ct) = encrypt(&key, msg, b"").unwrap();
        let dec = decrypt(&key, &nonce, &ct, b"").unwrap();

        assert_eq!(msg.to_vec(), dec);
    }

    #[test]
    fn tampering_is_detected() {
        let (alice_s, _) = pair();
        let (_, bob_p) = pair();
        let key = SessionKey::derive(&alice_s, &bob_p, b"test-salt").unwrap();

        let (nonce, mut ct) = encrypt(&key, b"secret", b"").unwrap();
        ct[0] ^= 0x01;
        assert_eq!(decrypt(&key, &nonce, &ct, b"").unwrap_err(), Error::Auth);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (alice_s, _) = pair();
        let (_, bob_p) = pair();
        let (carol_s, carol_p) = pair();

        let good = SessionKey::derive(&alice_s, &bob_p, b"test-salt").unwrap();
        let evil = SessionKey::derive(&carol_s, &carol_p, b"test-salt").unwrap();

        let (nonce, ct) = encrypt(&good, b"secret", b"").unwrap();
        assert_eq!(decrypt(&evil, &nonce, &ct, b"").unwrap_err(), Error::Auth);
    }

    #[test]
    fn aad_binds_chat() {
        let (alice_s, _) = pair();
        let (_, bob_p) = pair();
        let key = SessionKey::derive(&alice_s, &bob_p, b"test-salt").unwrap();

        let (nonce, ct) = encrypt(&key, b"secret", b"chat:team-anon").unwrap();
        assert_eq!(
            decrypt(&key, &nonce, &ct, b"chat:OTHER").unwrap_err(),
            Error::Auth
        );
    }
}