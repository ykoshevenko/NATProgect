//! natcore: ядро анонимного офлайн-мессенджера.
//!
//! Модули (архитектура):
//! - [`error`]      — [`Result`] и все типы ошибок ядра
//! - [`identity`]   — приватные ключи, публичные ключи, ник (анонимная личность)
//! - [`crypto`]     — E2EE: ECDH-сессии, ключи групп, шифрование/подписи
//! - [`network`]    — сессия «NAT-сети»: состав, invite-коды
//! - [`discovery`]  — UDP broadcast/multicast: поиск соседей в сети
//! - [`protocol`]   — типы сообщений на проводе (личное/группа/статус)
//! - [`transport`]  — TCP-каналы между узлами, установка соединений
//! - [`router`]     — mesh-маршрутизация и дедупликация
//! - [`chat`]       — чаты: ID, участники, ключи, история
//! - [`store`]      — сохранение данных устройства на диск
//!
//! Фасад [`Core`] (CRUD-интерфейс для NAT) добавляется сюда, когда модули
//! нижнего уровня будут готовы. Пока здесь только карта модулей.

pub mod chat;
pub mod crypto;
pub mod discovery;
pub mod error;
pub mod identity;
pub mod network;
pub mod protocol;
pub mod router;
pub mod store;
pub mod transport;