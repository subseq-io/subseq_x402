use std::borrow::Cow;
use std::fmt;

use anyhow::Error as AnyhowError;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Conflict,
    Database,
    Forbidden,
    InvalidInput,
    NotFound,
    Unauthorized,
    Upstream,
    Unknown,
}

impl ErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Conflict => "conflict",
            Self::Database => "database_error",
            Self::Forbidden => "forbidden",
            Self::InvalidInput => "invalid_input",
            Self::NotFound => "not_found",
            Self::Unauthorized => "unauthorized",
            Self::Upstream => "upstream_error",
            Self::Unknown => "unknown_error",
        }
    }
}

pub struct LibError {
    pub kind: ErrorKind,
    pub code: Cow<'static, str>,
    pub public: Cow<'static, str>,
    pub source: AnyhowError,
}

impl LibError {
    pub fn new(
        kind: ErrorKind,
        code: impl Into<Cow<'static, str>>,
        public: impl Into<Cow<'static, str>>,
        source: impl Into<AnyhowError>,
    ) -> Self {
        Self {
            kind,
            code: code.into(),
            public: public.into(),
            source: source.into(),
        }
    }

    pub fn from_kind(
        kind: ErrorKind,
        public: impl Into<Cow<'static, str>>,
        source: impl Into<AnyhowError>,
    ) -> Self {
        Self::new(kind, kind.code(), public, source)
    }

    pub fn conflict(public: impl Into<Cow<'static, str>>, source: impl Into<AnyhowError>) -> Self {
        Self::from_kind(ErrorKind::Conflict, public, source)
    }

    pub fn database(public: impl Into<Cow<'static, str>>, source: impl Into<AnyhowError>) -> Self {
        Self::from_kind(ErrorKind::Database, public, source)
    }

    pub fn forbidden(public: impl Into<Cow<'static, str>>, source: impl Into<AnyhowError>) -> Self {
        Self::from_kind(ErrorKind::Forbidden, public, source)
    }

    pub fn invalid(public: impl Into<Cow<'static, str>>, source: impl Into<AnyhowError>) -> Self {
        Self::from_kind(ErrorKind::InvalidInput, public, source)
    }

    pub fn not_found(public: impl Into<Cow<'static, str>>, source: impl Into<AnyhowError>) -> Self {
        Self::from_kind(ErrorKind::NotFound, public, source)
    }

    pub fn unauthorized(
        public: impl Into<Cow<'static, str>>,
        source: impl Into<AnyhowError>,
    ) -> Self {
        Self::from_kind(ErrorKind::Unauthorized, public, source)
    }

    pub fn upstream(public: impl Into<Cow<'static, str>>, source: impl Into<AnyhowError>) -> Self {
        Self::from_kind(ErrorKind::Upstream, public, source)
    }

    pub fn unknown(public: impl Into<Cow<'static, str>>, source: impl Into<AnyhowError>) -> Self {
        Self::from_kind(ErrorKind::Unknown, public, source)
    }
}

impl fmt::Display for LibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.public, self.source)
    }
}

impl fmt::Debug for LibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LibError")
            .field("kind", &self.kind)
            .field("code", &self.code)
            .field("public", &self.public)
            .field("source", &self.source)
            .finish()
    }
}

impl std::error::Error for LibError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub type Result<T, E = LibError> = core::result::Result<T, E>;
