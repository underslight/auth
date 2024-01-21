use dyn_clone::{DynClone, clone_trait_object};

/// This trait ensures that a struct can be used as a set of attributes.
/// 
/// Why do we need this? Well, since the attribute struct logically can't
/// have a known size at compile time, it's stored in a `Box<dyn UserAttribute>`.
/// This however becomes a problem when serializing, deserializing (which is necessary
/// in order to interact with the database), and cloning. But through the magic of the 
/// [typetag](https://docs.rs/typetag) crate we can do it:
/// 
/// Simply derive the [Clone], [Serialize](serde::Serialize), [Deserialize](serde::Deserialize), and [Debug](std::fmt::Debug) traits
/// for the attribute struct and them implement the [UserAttribute] trait. 
/// 
/// # Note
/// **A `#[typetag::serde]` macro must be included at the start of every UserAttribute `impl` block!**
/// 
/// # Example
/// ```ignore
/// use serde::{Serialize, Deserialize};
/// 
/// #[derive(Clone, Debug, Serialize, Deserialize)]
/// pub struct CustomAttributes {
///     pub name: String,
///     pub age: u32,
///     pub admin: bool,
///     // ...and so on
/// }
/// 
/// // Implements the UserAttribute trait
/// //
/// // Note: The #[typetag::serde] macro must be included at the start of every UserAttribute impl block!
/// #[typetag::serde]
/// impl UserAttribute for CustomAttributes {}
/// ```
#[typetag::serde(tag = "type")]
pub trait UserAttribute: DynClone + std::fmt::Debug + Send + Sync {}

clone_trait_object!(UserAttribute);