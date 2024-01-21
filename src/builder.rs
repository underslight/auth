use crate::prelude::*;

/// Declares that the type is [Buildable], which means that 
/// it can (and in most cases must) be initialized via the 
/// builder pattern.
/// 
/// # Example
/// ```ignore
/// use auth::builder::*;
/// 
/// // The complex struct we want to build
/// pub struct Something {
///     pub field: String,
/// }
/// 
/// impl Buildable for Something {
/// 
///     // Specifies the Builder type. This
///     // type must have the Builder trait.
///     type Builder = SomethingBuilder;
/// 
///     // This function returns the Builder type that should be 
///     // used to construct the Buildable struct. This method already
///     // has a default implementation, so you don't need to worry 
///     // about redefining it. 
///     fn builder() -> Self::Builder() {
/// 
///         // This is the default implementation
///         Self::Builder::new();
///     }
/// }
/// ```
pub trait Buildable {
    /// Specifies associated [Builder] type
    type Builder: Builder;

    /// Returns the [Builder] type that should be used to construct the 
    /// [Buildable] struct. This method already has a default implementation
    /// so you don't need to worry about redefining it.     
    fn builder() -> Self::Builder {
        Self::Builder::new()
    }
}

/// Declares that the type can be used to build the associated [Buildable] type.
/// 
/// After creating a new [Builder] struct, you can build it with the following methods:
///  - By calling [build](Builder::build) method, which can return an error (if it's implemented)
///  - By calling the [build_safe](Builder::build_safe) method, which will always succeed (if it's implemented)
/// 
/// # Example
/// ```ignore
/// use auth::prelude::*;
/// use auth::builder::*;
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
///     // This should always be the preferred method (if possible) for building:
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
pub trait Builder {
    /// The [Buildable] type associated with the this
    type Buildable: Buildable;

    /// Returns a new [Builder]
    fn new() -> Self;
    /// Builds the associated [Buildable]. This can return an error,
    /// but it should never panic.
    fn build(&self) -> AuthResult<Self::Buildable>;
    /// Builds the associated [Buildable]. This will always succeed.
    /// 
    /// # Note:
    /// Always check if this method has been implemented, if not use [build](Builder::build)
    fn build_safe(&self) -> Self::Buildable;
}
