//! Where a service can be reached, in the three forms deployment needs.
//!
//! The scheme is the deployment decision, and it is the *only* thing that
//! changes between a single VPS and twenty-four pods:
//!
//! | Written | Means |
//! |---|---|
//! | `http://text:50051` | across hosts; Kubernetes DNS fills the name in |
//! | `unix:/run/starling/text.sock` | co-located, and file permissions are the auth |
//! | `inproc:text` | `--all-in-one`, over an in-memory transport |

use std::path::PathBuf;
use std::str::FromStr;

/// A resolved service address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// A TCP endpoint, as a URI.
    Http(String),
    /// A Unix domain socket.
    Unix(PathBuf),
    /// Another service in this process.
    InProcess(String),
}

/// Why an endpoint string could not be understood.
#[derive(Debug, thiserror::Error)]
#[error("{0:?} is not an endpoint: write http://host:port, unix:/path or inproc:name")]
pub struct MalformedEndpoint(String);

impl FromStr for Endpoint {
    type Err = MalformedEndpoint;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        if let Some(path) = text.strip_prefix("unix:") {
            if path.is_empty() {
                return Err(MalformedEndpoint(text.to_owned()));
            }
            return Ok(Self::Unix(PathBuf::from(path)));
        }
        if let Some(name) = text.strip_prefix("inproc:") {
            if name.is_empty() {
                return Err(MalformedEndpoint(text.to_owned()));
            }
            return Ok(Self::InProcess(name.to_owned()));
        }
        if text.starts_with("http://") || text.starts_with("https://") {
            return Ok(Self::Http(text.to_owned()));
        }
        Err(MalformedEndpoint(text.to_owned()))
    }
}

impl Endpoint {
    /// The in-process endpoint for `service`.
    #[must_use]
    pub fn in_process(service: &str) -> Self {
        Self::InProcess(service.to_owned())
    }

    /// A short description for logs.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Http(uri) => uri.clone(),
            Self::Unix(path) => format!("unix:{}", path.display()),
            Self::InProcess(name) => format!("inproc:{name}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_documented_form_parses_to_its_transport() {
        assert_eq!(
            "http://text:50051".parse::<Endpoint>().ok(),
            Some(Endpoint::Http("http://text:50051".to_owned()))
        );
        assert_eq!(
            "unix:/run/starling/text.sock".parse::<Endpoint>().ok(),
            Some(Endpoint::Unix(PathBuf::from("/run/starling/text.sock")))
        );
        assert_eq!(
            "inproc:text".parse::<Endpoint>().ok(),
            Some(Endpoint::InProcess("text".to_owned()))
        );
    }

    #[test]
    fn a_bare_host_port_is_refused_rather_than_assumed_to_be_tcp() {
        // Assuming would make `unix` a typo away from silently opening a TCP
        // socket on a host that expected a file-permission boundary.
        assert!("text:50051".parse::<Endpoint>().is_err());
        assert!("unix:".parse::<Endpoint>().is_err());
    }
}
