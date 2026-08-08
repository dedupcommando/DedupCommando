// SPDX-License-Identifier: Apache-2.0
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AppError>;

/// The unified application error type.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("DB: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("serialization: {0}")]
    Json(#[from] serde_json::Error),

    /// The database file at the configured path is not the one this connection opened — it was
    /// replaced across the open itself, or between two later probes.
    ///
    /// Typed rather than folded into `Msg` because the recovery is control flow: the owner drops
    /// the connection and reopens, and a caller deciding that from rendered text would be a parser
    /// where a `match` belongs. `path` is already terminal-sanitized; `detail` is the sentence the
    /// operator reads.
    #[error("{detail}")]
    PathChanged { path: String, detail: String },

    #[error("{0}")]
    Msg(String),
}

impl AppError {
    pub fn msg(text: impl Into<String>) -> Self {
        AppError::Msg(text.into())
    }
}
