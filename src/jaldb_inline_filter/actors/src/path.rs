use std::fmt::{Debug, Display, Formatter};

/// A unique path to an [Actor] that locates it within the actor tree
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct ActorPath(pub(crate) Vec<String>);
impl ActorPath {
    pub(crate) fn new(path: &str) -> Self {
        let tokens = Self::tokenize(path);
        ActorPath(tokens)
    }

    /// Create a path that is a child of this path
    pub fn make_child(&self, p: &str) -> Self {
        let mut tokens = self.0.clone();
        tokens.push(p.to_owned());
        ActorPath(tokens)
    }

    /// Get the parent path of this path
    pub fn parent(&self) -> Option<ActorPath> {
        if self.0.len() > 1 {
            let mut tokens = self.0.clone();
            tokens.truncate(tokens.len() - 1);
            Some(ActorPath(tokens))
        } else {
            None
        }
    }

    // paths are implemented as ordered tokens, this splits a string into those tokens
    fn tokenize(path: &str) -> Vec<String> {
        path.split("/").fold(vec![], |mut acc, path| {
            acc.push(path.to_owned());
            acc
        })
    }
}

impl From<&str> for ActorPath {
    fn from(value: &str) -> Self {
        ActorPath::new(value)
    }
}

impl From<String> for ActorPath {
    fn from(value: String) -> Self {
        ActorPath::new(&value)
    }
}

impl Debug for ActorPath {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "/{}", &self.0.join("/"))
    }
}

impl Display for ActorPath {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "/{}", &self.0.join("/"))
    }
}
