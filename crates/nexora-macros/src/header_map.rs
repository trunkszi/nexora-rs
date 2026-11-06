use std::collections::HashSet;

use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::{
    Data, DeriveInput, Fields, GenericArgument, LitStr, PathArguments, Type, ext::IdentExt,
    spanned::Spanned,
};

use crate::literals::{validate_name, validate_value};

#[derive(Default)]
struct Options {
    name: Option<LitStr>,
    required: bool,
    default: Option<LitStr>,
}

fn parse_options(field: &syn::Field) -> syn::Result<Options> {
    let mut options = Options::default();
    let mut seen = HashSet::new();
    for attr in &field.attrs {
        if !attr.path().is_ident("header") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if let Some(key) = meta.path.get_ident()
                && !seen.insert(key.to_string())
            {
                return Err(meta.error("duplicate header option"));
            }
            if meta.path.is_ident("name") {
                options.name = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("required") {
                options.required = true;
            } else if meta.path.is_ident("default") {
                options.default = Some(meta.value()?.parse()?);
            } else {
                return Err(meta.error("expected name, required, or default"));
            }
            Ok(())
        })?;
    }
    Ok(options)
}

fn option_inner(ty: &Type) -> Option<&Type> {
    if let Type::Paren(ty) = ty {
        return option_inner(&ty.elem);
    }
    if let Type::Group(ty) = ty {
        return option_inner(&ty.elem);
    }
    let Type::Path(path) = ty else {
        return None;
    };
    if path.qself.is_some() {
        return None;
    }
    let segments = &path.path.segments;
    let standard = match segments.len() {
        1 => true,
        3 => {
            (segments[0].ident.unraw() == "std" || segments[0].ident.unraw() == "core")
                && segments[1].ident.unraw() == "option"
                && matches!(segments[0].arguments, PathArguments::None)
                && matches!(segments[1].arguments, PathArguments::None)
        }
        _ => false,
    };
    if !standard {
        return None;
    }
    let segment = path.path.segments.last()?;
    if segment.ident.unraw() != "Option" {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    if arguments.args.len() != 1 {
        return None;
    }
    match arguments.args.first()? {
        GenericArgument::Type(inner) => Some(inner),
        _ => None,
    }
}

pub(crate) fn expand(input: DeriveInput) -> syn::Result<TokenStream> {
    let headers_binding = binding(&input, "__nexora_headers");
    let value_binding = binding(&input, "__nexora_value");
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return Err(syn::Error::new(
                    data.fields.span(),
                    "HeaderMap requires a struct with named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new(
                input.span(),
                "HeaderMap can only be derived for a struct",
            ));
        }
    };
    let mut encoders = Vec::new();
    let mut decoders = Vec::new();
    let mut names = HashSet::new();
    let mut generics = input.generics.clone();
    for field in fields {
        let Some(ident) = &field.ident else {
            return Err(syn::Error::new(field.span(), "expected named field"));
        };
        let options = parse_options(field)?;
        let name = options.name.unwrap_or_else(|| {
            LitStr::new(
                &ident.to_string().trim_start_matches("r#").replace('_', "-"),
                ident.span(),
            )
        });
        validate_name(&name, false)?;
        if !names.insert(name.value().to_ascii_lowercase()) {
            return Err(syn::Error::new(
                name.span(),
                "multiple fields map to the same header name",
            ));
        }
        if let Some(default) = &options.default {
            validate_value(default)?;
        }
        let ty = &field.ty;
        let inner = option_inner(ty);
        let value_ty = inner.unwrap_or(ty);
        generics
            .make_where_clause()
            .predicates
            .push(syn::parse_quote!(
                #value_ty: ::std::string::ToString + ::std::str::FromStr
            ));
        if inner.is_some() {
            encoders.push(quote! {
                if let ::std::option::Option::Some(#value_binding) = &self.#ident {
                    #headers_binding.insert(
                        #name,
                        ::std::string::ToString::to_string(#value_binding),
                    );
                }
            });
        } else {
            encoders.push(quote! {
                #headers_binding.insert(
                    #name,
                    ::std::string::ToString::to_string(&self.#ident),
                );
            });
        }
        let has_default = options.default.is_some();
        let missing = if let Some(default) = options.default {
            quote! { #default }
        } else {
            quote! {
                return ::std::result::Result::Err(
                    ::nexora_proto::ProtoError::MissingHeader(::std::string::String::from(#name))
                );
            }
        };
        let parse = quote! {
            <#value_ty as ::std::str::FromStr>::from_str(#value_binding).map_err(|_| {
                ::nexora_proto::ProtoError::InvalidHeader(
                    ::std::format!("invalid value for header {}", #name)
                )
            })?
        };
        let decode = if inner.is_some() && !options.required {
            if has_default {
                quote! {
                    ::std::option::Option::Some({
                        let #value_binding = match #headers_binding.get(#name) {
                            ::std::option::Option::Some(#value_binding) => #value_binding,
                            ::std::option::Option::None => { #missing },
                        };
                        #parse
                    })
                }
            } else {
                quote! {
                    match #headers_binding.get(#name) {
                        ::std::option::Option::Some(#value_binding) => {
                            ::std::option::Option::Some(#parse)
                        }
                        ::std::option::Option::None => ::std::option::Option::None,
                    }
                }
            }
        } else {
            let parsed = if inner.is_some() {
                quote! { ::std::option::Option::Some(#parse) }
            } else {
                parse
            };
            quote! {{
                let #value_binding = match #headers_binding.get(#name) {
                    ::std::option::Option::Some(#value_binding) => #value_binding,
                    ::std::option::Option::None => { #missing },
                };
                #parsed
            }}
        };
        decoders.push(quote! { #ident: #decode });
    }
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    let capacity = fields.len();
    Ok(quote! {
        impl #impl_generics ::nexora_proto::HeaderMapExt for #name #type_generics #where_clause {
            fn to_headers(&self) -> ::nexora_proto::Headers {
                let mut #headers_binding = ::nexora_proto::Headers::with_capacity(#capacity);
                #(#encoders)*
                #headers_binding
            }

            fn from_headers(
                #headers_binding: &::nexora_proto::Headers,
            ) -> ::nexora_proto::Result<Self> {
                ::std::result::Result::Ok(Self { #(#decoders),* })
            }
        }
    })
}

fn binding(input: &DeriveInput, base: &str) -> Ident {
    let mut name = base.to_owned();
    while input
        .generics
        .const_params()
        .any(|parameter| parameter.ident.unraw() == name)
    {
        name.push('_');
    }
    Ident::new(&name, Span::mixed_site())
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use super::expand;

    #[test]
    fn rejects_invalid_shapes_and_ambiguous_header_mapping() {
        assert!(
            expand(parse_quote!(
                enum Invalid {
                    A,
                }
            ))
            .is_err()
        );
        assert!(
            expand(parse_quote!(
                struct Invalid(String);
            ))
            .is_err()
        );
        assert!(
            expand(parse_quote! {
                struct Invalid {
                    #[header(name = "X-Name")]
                    first: String,
                    #[header(name = "x-name")]
                    second: String,
                }
            })
            .is_err()
        );
    }

    #[test]
    fn rejects_unknown_duplicate_and_unsafe_attributes() {
        for input in [
            parse_quote!(
                struct Invalid {
                    #[header(unknown)]
                    value: String,
                }
            ),
            parse_quote!(
                struct Invalid {
                    #[header(required, required)]
                    value: String,
                }
            ),
            parse_quote!(
                struct Invalid {
                    #[header(default = "bad\n")]
                    value: String,
                }
            ),
        ] {
            assert!(expand(input).is_err());
        }
    }

    #[test]
    fn accepts_generics_optional_required_and_default_fields() {
        assert!(
            expand(parse_quote! {
                struct Example<T> {
                    #[header(name = "x-value")]
                    value: T,
                    absent: Option<String>,
                    #[header(required)]
                    required: Option<u64>,
                    #[header(default = "42")]
                    fallback: u64,
                }
            })
            .is_ok()
        );
    }
}
