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

    #[error("{0}")]
    Msg(String),
}

impl AppError {
    pub fn msg(text: impl Into<String>) -> Self {
        AppError::Msg(text.into())
    }
}
