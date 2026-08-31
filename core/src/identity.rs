// TODO: X25519 ключевая пара, публичный ключ, случайный ник.
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct Identity {
    secret: StaticSecret,
    public: PublicKey,
    nick: String,
}

impl Identity {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let nick = random_nick();
        Self { secret, public, nick }
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn nick(&self) -> &str {
        &self.nick
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn from_bytes(secret_bytes: [u8; 32], nick: String) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public, nick }
    }
}

fn random_nick() -> String {
    const ANIMALS: [&str; 5] = ["Лис", "Барсук", "Сыч", "Олень", "Енот"];
    let mut b = [0u8; 4];
    OsRng.fill_bytes(&mut b);
    let animal = ANIMALS[u32::from_le_bytes(b) as usize % ANIMALS.len()];
    let number = u32::from_le_bytes(b) % 1000;
    format!("{animal} {number:03}")
}