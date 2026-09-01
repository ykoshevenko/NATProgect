// TODO: NetworkSession: имя сети, invite-код, участники, статус (host/в сети).
use std::fmt;
use rand_core::{OsRng, RngCore};
use x25519_dalek::PublicKey;

const CODE_BYTES: usize = 5;
const CODE_CHARS: usize = 8;
const SEPARATOR: usize = 4;
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug, Clone)]
pub struct NetworkCode(String);

pub struct Participant {
    pub public_key:PublicKey,
    pub nick: String,
    pub status: ParticipantStatus,
}

pub enum ParticipantStatus {
    Online,
    Offline,
    Connecting,
}

pub enum NetworkStatus {
    Disconnected,
    InRoom,
}

pub struct Network {
    pub name:String,
    pub salt:[u8;32],
    pub code: NetworkCode,
    pub host_public_key: Option<PublicKey>,
    pub participants: Vec<Participant>,
}

#[derive(Debug)]
pub enum NetworkError {
    InvalidInviteCode,
    InvalidName,
    DuplicateParticipant,
}

impl fmt::Display for NetworkError {
    fn fmt(&self,f:&mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::InvalidInviteCode => write!(f,"некорректный код приглашения"),
            NetworkError::InvalidName => write!(f,"имя комнаты пустое или длиннее 64 символов"),
            NetworkError::DuplicateParticipant => write!(f,"участник уже есть в комнате")
        }
    }
}

impl fmt::Display for NetworkStatus {
    fn fmt(&self,f:&mut fmt::Formatter<'_>) -> fmt::Result{
        match self {
            NetworkStatus::Disconnected => write!(f,"вне сети"),
            NetworkStatus::InRoom => write!(f,"в сети"),
        }
    }
}

impl NetworkCode {
    pub fn new(salt: &[u8; 32]) -> Self {
        let mut buf: u64 = 0;
        let mut bits: u64 = 0;
        let mut out = String::with_capacity(CODE_CHARS + 1);
        for i in 0..CODE_BYTES {
            buf = (buf << 8) | u64::from(salt[i]);
            bits += 8;
        }
        for i in 0..CODE_CHARS {
            if i == SEPARATOR {
                out.push('-');
            }
            bits -= 5;
            let idx = ((buf >> bits) & 0x1F) as u8;
            out.push(BASE32_ALPHABET[idx as usize] as char);
        }
        Self(out)
    }

    pub fn parse(s: &str) -> Result<Self, NetworkError> {
        let bytes = s.as_bytes();
        if bytes.len() != CODE_CHARS + 1 {
            return Err(NetworkError::InvalidInviteCode);
        }
        if bytes[SEPARATOR] != b'-' {
            return Err(NetworkError::InvalidInviteCode);
        }
        for (i, &b) in bytes.iter().enumerate() {
            if i == SEPARATOR {
                continue;
            }
            if !BASE32_ALPHABET.contains(&b) {
                return Err(NetworkError::InvalidInviteCode);
            }
        }
        let clean: String = bytes
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != SEPARATOR)
            .map(|(_, &b)| b as char)
            .collect();
        let formatted = format!("{}-{}", &clean[..SEPARATOR], &clean[SEPARATOR..]);
        Ok(Self(formatted))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn matches_salt(&self, salt: &[u8; 32]) -> bool {
        Self::new(salt).0 == self.0
    }
}

impl Network {
    pub fn create(name: &str, host_pub: PublicKey, host_nick: &str) -> (Self, [u8; 32]) {
        let mut salt = [0u8; 32];
        get_random_bytes(&mut salt);
        let code = NetworkCode::new(&salt);
        let participant = Participant {
            public_key: host_pub,
            nick: host_nick.to_string(),
            status: ParticipantStatus::Online,
        };
        let network = Network {
            name: name.to_string(),
            salt,
            code,
            host_public_key: Some(host_pub),
            participants: vec![participant],
        };
        (network, salt)
    }

    pub fn join(
        code: &NetworkCode,
        salt: &[u8; 32],
        my_pub: PublicKey,
        my_nick: &str,
    ) -> Result<Self, NetworkError> {
        if !code.matches_salt(salt) {
            return Err(NetworkError::InvalidInviteCode);
        }
        let participant = Participant {
            public_key: my_pub,
            nick: my_nick.to_string(),
            status: ParticipantStatus::Connecting,
        };
        Ok(Network {
            name: String::new(),
            salt: *salt,
            code: code.clone(),
            host_public_key: None,
            participants: vec![participant],
        })
    }

    pub fn leave(&mut self) {
        self.participants.clear();
    }

    pub fn add_participant(&mut self, pub_key: PublicKey, nick: &str) -> Result<(), NetworkError> {
        if self.participants.iter().any(|p| p.public_key == pub_key) {
            return Err(NetworkError::DuplicateParticipant);
        }
        self.participants.push(Participant {
            public_key: pub_key,
            nick: nick.to_string(),
            status: ParticipantStatus::Online,
        });
        Ok(())
    }

    pub fn remove_participant(&mut self, pub_key: &PublicKey) {
        self.participants.retain(|p| p.public_key != *pub_key);
    }

    pub fn find_participant(&self, pub_key: &PublicKey) -> Option<&Participant> {
        self.participants.iter().find(|p| p.public_key == *pub_key)
    }

    pub fn participants(&self) -> &[Participant] {
        &self.participants
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn code(&self) -> &NetworkCode {
        &self.code
    }

    pub fn is_host(&self, pub_key: &PublicKey) -> bool {
        self.host_public_key.as_ref() == Some(pub_key)
    }
}

fn get_random_bytes(buf: &mut [u8; 32]) {
    let mut rng = OsRng;
    rng.fill_bytes(buf);
}

//test

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};
    use rand_core::OsRng;

    fn gen_keys() -> (StaticSecret, PublicKey) {
        let s = StaticSecret::random_from_rng(OsRng);
        let p = PublicKey::from(&s);
        (s, p)
    }

    #[test]
    fn code_roundtrip() {
        let salt = [1u8; 32];
        let code = NetworkCode::new(&salt);
        let parsed = NetworkCode::parse(code.as_str()).unwrap();
        assert_eq!(code.as_str(), parsed.as_str());
        assert!(parsed.matches_salt(&salt));
    }

    #[test]
    fn parse_rejects_bad() {
        let bad = NetworkCode::parse("ZZ-ZZ-ZZ-ZZ");
        assert!(bad.is_err());
        let bad2 = NetworkCode::parse("ABCD-EFGH-extra");
        assert!(bad2.is_err());
    }

    #[test]
    fn create_populates_host() {
        let (_, p) = gen_keys();
        let (net, _) = Network::create("test", p, "Лис 042");
        assert_eq!(net.name, "test");
        assert!(net.is_host(&p));
        assert_eq!(net.participants().len(), 1);
        assert_eq!(net.participants()[0].nick, "Лис 042");
    }

    #[test]
    fn join_valid() {
        let (net, salt) = Network::create("test", gen_keys().1, "Хост");
        let (_, my_pub) = gen_keys();
        let net2 = Network::join(net.code(), &salt, my_pub, "Барсук 001").unwrap();
        assert_eq!(net2.participants().len(), 1);
        assert!(net2.find_participant(&my_pub).is_some());
        assert_eq!(net2.code().as_str(), net.code().as_str());
    }

    #[test]
    fn join_invalid_code() {
        let salt = [1u8; 32];
        let bad_code = NetworkCode::parse("ABCD-EFGH").unwrap();
        let (_, my_pub) = gen_keys();
        let res = Network::join(&bad_code, &salt, my_pub, "Барсук 001");
        assert!(res.is_err());
    }

    #[test]
    fn add_duplicate_rejected() {
        let (_, p) = gen_keys();
        let (mut net, _) = Network::create("test", p, "Хост");
        let (_, other) = gen_keys();
        net.add_participant(other, "Друг").unwrap();
        let res = net.add_participant(other, "Друг");
        assert!(res.is_err());
    }

    #[test]
    fn remove_participant() {
        let (_, p) = gen_keys();
        let (mut net, _) = Network::create("test", p, "Хост");
        let (_, other) = gen_keys();
        net.add_participant(other, "Друг").unwrap();
        net.remove_participant(&other);
        assert!(net.find_participant(&other).is_none());
    }

    #[test]
    fn find_and_status() {
        let (_, p) = gen_keys();
        let (net, _) = Network::create("test", p, "Хост");
        assert!(net.find_participant(&p).is_some());
        assert_eq!(format!("{}", NetworkStatus::InRoom), "в сети");
        assert_eq!(format!("{}", NetworkStatus::Disconnected), "вне сети");
    }
}