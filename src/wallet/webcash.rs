//! Webcash types re-exported from [`webylib`].
//!
//! The harmoniis-wallet crate depends on webylib internally. This module
//! re-exports the commonly used types so that consumers (backend, agent)
//! only need to depend on harmoniis-wallet.

pub use webylib::amount::Amount;
pub use webylib::webcash::{SecretWebcash, PublicWebcash};
pub use webylib::wallet::{Wallet as WebcashWallet, WalletSnapshot as WebcashWalletSnapshot};
pub use webylib::server::ServerClient as WebcashServerClient;
pub use webylib::hd::HDWallet as WebcashHDWallet;
pub use webylib::ChainCode as WebcashChainCode;
pub use webylib::error::Error as WebcashError;
