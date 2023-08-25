use std::fmt::Display;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FileLoadError {
    FileError(io::Error),
    DeserializeError(serde_json::Error),
}

impl From<serde_json::Error> for FileLoadError {
    fn from(e: serde_json::Error) -> Self {
        Self::DeserializeError(e)
    }
}

impl From<io::Error> for FileLoadError {
    fn from(e: io::Error) -> Self {
        Self::FileError(e)
    }
}

impl Display for FileLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            FileLoadError::FileError(e) => {
                f.write_fmt(format_args!("could not open file due to error {:?}", e))
            }
            FileLoadError::DeserializeError(e) => f.write_fmt(format_args!(
                "could not deserialize file due to error {:?}",
                e
            )),
        }
    }
}
