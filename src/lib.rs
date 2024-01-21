// #![warn(missing_docs)]

//! Just an auth crate

/// Traits for the builder pattern
/// 
/// The builder pattern allows the API's consumer to create
/// a complex struct in a programmatic and ergonomic way while
/// also allowing error handling.
/// 
/// # Example
/// ```ignore
/// use auth::prelude::*;
/// use auth::builder::*;
/// 
/// // The complex struct we want to build
/// pub struct Something {
///     pub field: String,
/// }
/// 
/// // We declare the the Something struct is buildable.
/// // In this case we dont need to declare the builder()
/// // method since the default implementation works just fine.
/// impl Buildable for Something {
/// 
///     // Defines the builder struct 
///     type Builder = SomethingBuilder;
/// }
/// 
/// // The builder for the something struct. It should have same
/// // fields as the struct it's going to build, but all the types
/// // should be Option<T> instead of T.
/// //
/// // The fields can be set by hand, or we can (and should) provide
/// // some setter methods in the Builder's impl block.
/// #[derive(Default)]
/// pub struct SomethingBuilder {
///     pub field: Option<String>
/// }
/// 
/// impl Builder for SomethingBuilder {
/// 
///     // Defines the struct we're going to build
///     type Buildable = Something;
/// 
///     // Returns a Builder struct. 
///     // Since we derive Default, we can just use that
///     // to give us an empty Builder struct.
///     fn new() -> Self {
///         Self::default()
///     }
/// 
///     // The build function should always be implemented even if build_safe()
///     // is implemented and an error or panic isn't possible.
///     fn build(&self) -> AuthResult<Self::Buildable> {
///         Ok(Self::Buildable {
///             field: match &self.field {
///                 Some(field) => field.clone(),
///                 None => panic!(), // This should just return an error
///             }
///         })
///     }
/// 
///     // This is always be the preferred method (if possible):
///     // it constructs the Buildable struct without returning errors.
///     fn build_safe(&self) -> Self::Buildable {
///         Self::Buildable {
///             field: match &self.field {
///                 Some(field) => field.clone(),
///                 None => "some_default".into(),
///             }
///         }
///     }
/// }
/// 
/// // Here we can provide some handy setter methods
/// impl SomethingBuilder {
///     
///     // Sets the field
///     pub fn field(&mut self, field: String) -> &mut Self {
///         self.field = Some(field);
///         self
///     } 
/// }
/// ```
pub mod builder;

/// Database operations
pub mod database;

/// Error propagation and messages
///
/// Error handling in this crate is relatively simple:
/// we have a single [AuthError](crate::error::AuthError) enum which contains every
/// possible type of error (and a generic one to avoid getting _too_ specific).
/// Currently none of the error branches contain additional metadata, but this will 
/// change relatively soon.
pub mod error;

/// Commonly used structs and modules
pub mod prelude;

/// [User](crate::user::User) operations 
pub mod user;
