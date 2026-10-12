/// Mirrors dart_jwk_duo's three exception kinds 1:1, so the Dart binding can
/// map them back without loss: Format = FormatException, State = StateError,
/// Argument = ArgumentError.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Format(String),
    #[error("{0}")]
    State(String),
    #[error("{0}")]
    Argument(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn format(msg: impl Into<String>) -> Error { Error::Format(msg.into()) }
pub(crate) fn state(msg: impl Into<String>) -> Error { Error::State(msg.into()) }
pub(crate) fn argument(msg: impl Into<String>) -> Error { Error::Argument(msg.into()) }
