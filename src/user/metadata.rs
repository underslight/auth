use crate::builder::*;
use crate::prelude::*;

use serde::Deserialize;
use serde::Serialize;

/// Contains the auth metadata for a [User]
/// 
/// Todo:
/// [ ] Last access location
/// [ ] Last password
/// [ ] Disabled reason
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct UserMetadata {
    /// Whether or not the account is currently disabled
    pub disabled: bool,
    /// Whether or not the account is currently verified
    pub verified: bool,
    /// The last authentication timestamp
    pub last_access: u64,
    /// The last reset timestamp
    pub last_reset: u64,

}

impl Default for UserMetadata {
    fn default() -> Self {
        Self::builder().build_safe()
    }
}

impl Buildable for UserMetadata {
    type Builder = UserMetadataBuilder;
}

/// The [UserMetadata] builder struct
/// 
/// # Example
/// ```ignore
/// let timestamp = get_current_timestamp();
/// let user_metadata = UserMetadata::builder() // Gets the builder
///     .disabled(true)
///     .verified(true)
///     .last_access(timestamp)
///     .last_reset(timestamp)
///     .build_safe();
/// ```
#[derive(Clone, Debug)]
pub struct UserMetadataBuilder {
    pub disabled: Option<bool>,
    pub verified: Option<bool>,
    pub last_access: Option<u64>,
    pub last_reset: Option<u64>,
}

impl Default for UserMetadataBuilder {
    fn default() -> Self {
        let timestamp = jsonwebtoken::get_current_timestamp();

        Self {
            disabled: Some(false),
            verified: Some(false),
            last_access: Some(timestamp),
            last_reset: Some(timestamp),
        }
    }
}

impl Builder for UserMetadataBuilder {
    type Buildable = UserMetadata;

    fn new() -> Self {
        Self::default()
    }

    fn build(&self) -> AuthResult<Self::Buildable> {
        Ok(self.build_safe())
    }

    fn build_safe(&self) -> Self::Buildable {
        Self::Buildable {
            disabled: match self.disabled {
                Some(disabled) => disabled,
                None => false,
            },
            verified: match self.verified {
                Some(verified) => verified,
                None => false,
            },
            last_access: match self.last_access {
                Some(last_access) => last_access,
                None => jsonwebtoken::get_current_timestamp(),
            },
            last_reset: match self.last_reset {
                Some(last_reset) => last_reset,
                None => jsonwebtoken::get_current_timestamp(),
            },
        }
    }
}

impl UserMetadataBuilder {

    /// Sets the disabled flag
    /// 
    /// # Example
    /// ```ignore
    /// let metadata = UserMetadata::builder()
    ///     .disabled(true)
    ///     .build_safe();
    /// ```
    pub fn disabled(&mut self, disabled: bool) -> &mut Self {
        self.disabled = Some(disabled);
        self
    }

    /// Sets the verified flag
    /// 
    /// # Example
    /// ```ignore
    /// let metadata = UserMetadata::builder()
    ///     .verified(true)
    ///     .build_safe();
    /// ```
    pub fn verified(&mut self, verified: bool) -> &mut Self {
        self.verified = Some(verified);
        self
    }

    /// Sets the last access timestamp
    /// 
    /// # Example
    /// ```ignore
    /// let metadata = UserMetadata::builder()
    ///     .last_access(get_current_timestamp())
    ///     .build_safe();
    /// ```
    pub fn last_access(&mut self, last_access: u64) -> &mut Self {
        self.last_access = Some(last_access);
        self
    }

    /// Sets the last password reset timestamp
    /// 
    /// # Example
    /// ```ignore
    /// let metadata = UserMetadata::builder()
    ///     .last_reset(get_current_timestamp)
    ///     .build_safe();
    /// ```
    pub fn last_reset(&mut self, last_reset: u64) -> &mut Self {
        self.last_reset = Some(last_reset);
        self
    }
}

#[cfg(test)]
mod test {
    use super::UserMetadata;
    use crate::builder::*;

    #[test]
    fn metadata_builder_build() {
        let metadata_safe = UserMetadata::builder()
            .build_safe();

        let metadata = UserMetadata::builder()
            .build()
            .unwrap();

        assert_eq!(metadata_safe, metadata)
    }

    #[test]
    fn metadata_builder_disabled() {
        let metadata = UserMetadata::builder()
            .disabled(true)
            .build_safe();

        assert_eq!(metadata.disabled, true)
    }

    #[test]
    fn metadata_builder_verified() {
        let metadata = UserMetadata::builder()
            .verified(true)
            .build_safe();

        assert_eq!(metadata.verified, true)
    }

    #[test]
    fn metadata_builder_last_access() {
        let metadata = UserMetadata::builder()
            .last_access(0)
            .build_safe();

        assert_eq!(metadata.last_access, 0)
    }

    #[test]
    fn metadata_builder_last_reset() {
        let metadata = UserMetadata::builder()
            .last_reset(0)
            .build_safe();

        assert_eq!(metadata.last_reset, 0)
    }
}