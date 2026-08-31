// TODO: enum Error и Result<T> для всего ядра (asio + exception как в C++).
use thiserror::Error;

#[derive(Debug,Error,PartialEq,Eq)]
pub enum Error {
    #[error("некорректный ключ: {0}")]
    InvalidKey(String),

    #[error("не удалось зашифровать")]
    Encrypt,

    #[error("не удалось расшифровать")]
    Decrypt,

    #[error("нарушена целостность данных (подделка)")]
    Auth,
}

pub type Result<T> = std::result::Result<T, Error>;

// test

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_displays_nicely() {
        let e = Error::InvalidKey("nonce".into());
        assert!(e.to_string().contains("некорректный ключ"));
    }
}