use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Span, TokenStream, TokenTree};
use quote::quote;
use syn::{
    Attribute, Data, DeriveInput, Field, Fields, Ident, LitStr, Type, ext::IdentExt, parse::Parser,
    parse_quote, spanned::Spanned,
};

enum Placement {
    Path,
    Query(LitStr),
    Header(LitStr),
    Body,
    JsonBody,
}

enum PathPart {
    Literal(LitStr),
    Parameter(String),
}

pub(crate) fn expand(input: DeriveInput) -> syn::Result<TokenStream> {
    let path_ident = fresh_ident(&input.generics, "__nexora_path");
    let query_started_ident = fresh_ident(&input.generics, "__nexora_query_started");
    let value_ident = fresh_ident(&input.generics, "__nexora_value");
    let text_ident = fresh_ident(&input.generics, "__nexora_text");
    let request_ident = fresh_ident(&input.generics, "__nexora_request");
    let body_ident = fresh_ident(&input.generics, "__nexora_body");
    let url_ident = fresh_ident(&input.generics, "__nexora_url");
    let uri_ident = fresh_ident(&input.generics, "__nexora_uri");
    let encode_ident = fresh_ident(&input.generics, "__nexora_encode");
    let base_url_ident = fresh_ident(&input.generics, "base_url");
    let error_ident = fresh_ident(&input.generics, "error");
    let byte_ident = fresh_ident(&input.generics, "byte");
    let (method, path) = configuration(&input.attrs, input.ident.span())?;
    let parts = parse_path(&path)?;
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    &input.ident,
                    "RestRequest requires named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "RestRequest requires a struct",
            ));
        }
    };
    let mut parameters = BTreeMap::new();
    let mut queries = Vec::new();
    let mut headers = Vec::new();
    let mut body = None;
    let mut bounds: Vec<syn::WherePredicate> = Vec::new();
    let type_parameters: BTreeSet<String> = input
        .generics
        .type_params()
        .map(|parameter| parameter.ident.to_string())
        .collect();
    for field in fields {
        let Some(placement) = placement(field)? else {
            continue;
        };
        let Some(ident) = &field.ident else { continue };
        let optional = option_inner(&field.ty);
        let value_type = optional.unwrap_or(&field.ty);
        let needs_bound = references_type_parameter(quote!(#value_type), &type_parameters);
        match placement {
            Placement::Path => {
                if optional.is_some() {
                    return Err(syn::Error::new_spanned(
                        field,
                        "path parameters cannot be optional",
                    ));
                }
                parameters.insert(field_name(ident), ident.clone());
                if needs_bound {
                    bounds.push(parse_quote!(#value_type: ::core::fmt::Display));
                }
            }
            Placement::Query(name) => {
                let append = quote! {
                    if #query_started_ident {
                        #path_ident.push('&');
                    } else {
                        #path_ident.push('?');
                        #query_started_ident = true;
                    }
                    #encode_ident(&mut #path_ident, #name);
                    #path_ident.push('=');
                    #encode_ident(&mut #path_ident, &::std::string::ToString::to_string(#value_ident));
                };
                queries.push(with_value(ident, optional.is_some(), &value_ident, append));
                if needs_bound {
                    bounds.push(parse_quote!(#value_type: ::core::fmt::Display));
                }
            }
            Placement::Header(name) => {
                let insert = quote! {
                    let #text_ident = ::std::string::ToString::to_string(#value_ident);
                    if #text_ident.bytes().any(|#byte_ident| #byte_ident == 127 || (#byte_ident < 32 && #byte_ident != b'\t')) {
                        return ::core::result::Result::Err(::nexora_proto::ProtoError::InvalidHeader(
                            ::std::format!("invalid value for header {}", #name),
                        ));
                    }
                    #request_ident.headers.insert(#name, #text_ident);
                };
                headers.push(with_value(ident, optional.is_some(), &value_ident, insert));
                if needs_bound {
                    bounds.push(parse_quote!(#value_type: ::core::fmt::Display));
                }
            }
            Placement::Body | Placement::JsonBody => {
                if body.is_some() {
                    return Err(syn::Error::new_spanned(
                        field,
                        "only one body field is allowed",
                    ));
                }
                let assignment = if matches!(placement, Placement::JsonBody) {
                    quote! {
                        let #body_ident = ::sonic_rs::to_vec(#value_ident).map_err(|#error_ident| {
                            ::nexora_proto::ProtoError::Http1Protocol(
                                ::std::format!("JSON body serialization failed: {}", #error_ident),
                            )
                        })?;
                        #request_ident.body = ::nexora_proto::Bytes::from(#body_ident);
                        if !#request_ident.headers.contains("content-type") {
                            #request_ident.headers.insert("content-type", "application/json");
                        }
                    }
                } else {
                    if needs_bound {
                        bounds.push(parse_quote!(#value_type: ::core::convert::AsRef<[u8]>));
                    }
                    quote! {
                        #request_ident.body = ::nexora_proto::Bytes::copy_from_slice(
                            ::core::convert::AsRef::<[u8]>::as_ref(#value_ident),
                        );
                    }
                };
                body = Some(with_value(
                    ident,
                    optional.is_some(),
                    &value_ident,
                    assignment,
                ));
            }
        }
    }
    let path_statements = bind_path(parts, &parameters, path.span(), &path_ident, &encode_ident)?;
    let encoder = if parameters.is_empty() && queries.is_empty() {
        TokenStream::new()
    } else {
        encoder(&input.generics, &encode_ident)
    };
    let query_flag = if queries.is_empty() {
        TokenStream::new()
    } else {
        quote!(let mut #query_started_ident = false;)
    };
    let mut generics = input.generics;
    generics.make_where_clause().predicates.extend(bounds);
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    let name = input.ident;
    Ok(quote! {
        impl #impl_generics #name #type_generics #where_clause {
            /// Builds the encoded request path and query string.
            ///
            /// Path parameters and query names and values use UTF-8 percent encoding.
            /// Optional query fields are omitted when absent.
            ///
            /// # Errors
            /// This method returns the encoded path directly.
            ///
            /// # Panics
            /// This method has no explicit panic paths.
            pub fn build_path_and_query(&self) -> ::std::string::String {
                #encoder
                let mut #path_ident = ::std::string::String::new();
                #(#path_statements)*
                #query_flag
                #(#queries)*
                #path_ident
            }

            /// Builds an HTTP request relative to the supplied absolute base URL.
            ///
            /// Raw body fields must implement `AsRef<[u8]>`. JSON body fields require
            /// a direct `sonic-rs` dependency and a `serde::Serialize` implementation.
            /// Generic JSON fields must declare their serialization bounds explicitly.
            ///
            /// # Errors
            /// Returns a protocol error for an invalid base URL, invalid header value,
            /// or a body that cannot be serialized as JSON.
            ///
            /// # Panics
            /// This method has no explicit panic paths.
            #[allow(clippy::wrong_self_convention)]
            pub fn into_request(&self, #base_url_ident: &str) -> ::nexora_proto::Result<::nexora_proto::Request> {
                if #base_url_ident.contains('?') || #base_url_ident.contains('#') {
                    return ::core::result::Result::Err(::nexora_proto::ProtoError::InvalidUri(
                        ::std::string::String::from(#base_url_ident),
                    ));
                }
                let _ = ::nexora_proto::Uri::parse(#base_url_ident)?;
                let #url_ident = ::std::format!(
                    "{}{}", #base_url_ident.trim_end_matches('/'), self.build_path_and_query(),
                );
                let #uri_ident = ::nexora_proto::Uri::parse(&#url_ident)?;
                let mut #request_ident = ::nexora_proto::Request::new(#method, #uri_ident);
                #(#headers)*
                #body
                ::core::result::Result::Ok(#request_ident)
            }
        }
    })
}

fn references_type_parameter(tokens: TokenStream, parameters: &BTreeSet<String>) -> bool {
    tokens.into_iter().any(|token| match token {
        TokenTree::Ident(ident) => parameters.contains(&ident.to_string()),
        TokenTree::Group(group) => references_type_parameter(group.stream(), parameters),
        _ => false,
    })
}

fn configuration(attrs: &[Attribute], span: Span) -> syn::Result<(TokenStream, LitStr)> {
    let mut method = None;
    let mut path = None;
    let mut present = false;
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("rest")) {
        if present {
            return Err(syn::Error::new_spanned(attr, "duplicate rest attribute"));
        }
        present = true;
        attr.parse_nested_meta(|meta| {
            let target = if meta.path.is_ident("method") {
                &mut method
            } else if meta.path.is_ident("path") {
                &mut path
            } else {
                return Err(meta.error("expected method or path"));
            };
            if target.is_some() {
                return Err(meta.error("duplicate rest option"));
            }
            *target = Some(meta.value()?.parse::<LitStr>()?);
            Ok(())
        })?;
    }
    let method = method.ok_or_else(|| syn::Error::new(span, "missing rest method"))?;
    let path = path.ok_or_else(|| syn::Error::new(span, "missing rest path"))?;
    let variant = match method.value().as_str() {
        "GET" => "Get",
        "POST" => "Post",
        "PUT" => "Put",
        "DELETE" => "Delete",
        "HEAD" => "Head",
        "OPTIONS" => "Options",
        "PATCH" => "Patch",
        "CONNECT" => "Connect",
        "TRACE" => "Trace",
        _ => return Err(syn::Error::new_spanned(method, "unsupported HTTP method")),
    };
    let variant = Ident::new(variant, method.span());
    Ok((quote!(::nexora_proto::Method::#variant), path))
}

fn placement(field: &Field) -> syn::Result<Option<Placement>> {
    let mut result = None;
    for attr in &field.attrs {
        let placement = if attr.path().is_ident("path_param") {
            require_bare(attr)?;
            Placement::Path
        } else if attr.path().is_ident("query") {
            let fallback = field.ident.as_ref().map(field_name).unwrap_or_default();
            Placement::Query(named_attribute(attr, Some(fallback))?)
        } else if attr.path().is_ident("header") {
            let name = named_attribute(attr, None)?;
            if !valid_header_name(&name.value()) {
                return Err(syn::Error::new_spanned(name, "invalid HTTP header name"));
            }
            Placement::Header(LitStr::new(&name.value().to_ascii_lowercase(), name.span()))
        } else if attr.path().is_ident("body") {
            require_bare(attr)?;
            Placement::Body
        } else if attr.path().is_ident("json_body") {
            require_bare(attr)?;
            Placement::JsonBody
        } else {
            continue;
        };
        if result.is_some() {
            return Err(syn::Error::new_spanned(
                attr,
                "a field can have only one REST placement",
            ));
        }
        result = Some(placement);
    }
    Ok(result)
}

fn require_bare(attr: &Attribute) -> syn::Result<()> {
    if matches!(attr.meta, syn::Meta::Path(_)) {
        Ok(())
    } else {
        Err(syn::Error::new_spanned(
            attr,
            "this attribute does not accept arguments",
        ))
    }
}

fn named_attribute(attr: &Attribute, fallback: Option<String>) -> syn::Result<LitStr> {
    let mut name = None;
    if !matches!(attr.meta, syn::Meta::Path(_)) {
        attr.parse_nested_meta(|meta| {
            if !meta.path.is_ident("name") {
                return Err(meta.error("expected name"));
            }
            if name.is_some() {
                return Err(meta.error("duplicate name"));
            }
            name = Some(meta.value()?.parse::<LitStr>()?);
            Ok(())
        })?;
    }
    let name = name.or_else(|| fallback.map(|value| LitStr::new(&value, attr.span())));
    name.ok_or_else(|| syn::Error::new_spanned(attr, "missing name"))
}

fn option_inner(ty: &Type) -> Option<&Type> {
    if let Type::Paren(ty) = ty {
        return option_inner(&ty.elem);
    }
    if let Type::Group(ty) = ty {
        return option_inner(&ty.elem);
    }
    let Type::Path(path) = ty else { return None };
    if path.qself.is_some() {
        return None;
    }
    let segments = &path.path.segments;
    let standard = match segments.len() {
        1 => true,
        3 => {
            (segments[0].ident.unraw() == "std" || segments[0].ident.unraw() == "core")
                && segments[1].ident.unraw() == "option"
                && matches!(segments[0].arguments, syn::PathArguments::None)
                && matches!(segments[1].arguments, syn::PathArguments::None)
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
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    if arguments.args.len() != 1 {
        return None;
    }
    match arguments.args.first()? {
        syn::GenericArgument::Type(inner) => Some(inner),
        _ => None,
    }
}

fn field_name(ident: &Ident) -> String {
    let name = ident.to_string();
    name.strip_prefix("r#").unwrap_or(&name).to_owned()
}

fn with_value(
    ident: &Ident,
    optional: bool,
    value_ident: &Ident,
    operation: TokenStream,
) -> TokenStream {
    if optional {
        quote! {
            if let ::core::option::Option::Some(#value_ident) = &self.#ident {
                #operation
            }
        }
    } else {
        quote! {
            {
                let #value_ident = &self.#ident;
                #operation
            }
        }
    }
}

fn parse_path(path: &LitStr) -> syn::Result<Vec<PathPart>> {
    let value = path.value();
    if !value.starts_with('/') || value.contains(['?', '#']) {
        return Err(syn::Error::new_spanned(
            path,
            "REST path must start with / and exclude query or fragment",
        ));
    }
    if value.bytes().any(|byte| byte <= 32 || byte == 127) {
        return Err(syn::Error::new_spanned(
            path,
            "REST path contains whitespace or control bytes",
        ));
    }
    let mut parts = Vec::new();
    let mut tail = value.as_str();
    while let Some(start) = tail.find('{') {
        let literal = &tail[..start];
        if literal.contains('}') {
            return Err(syn::Error::new_spanned(
                path,
                "unmatched closing path brace",
            ));
        }
        parts.push(PathPart::Literal(LitStr::new(literal, path.span())));
        tail = &tail[start + 1..];
        let end = tail
            .find('}')
            .ok_or_else(|| syn::Error::new_spanned(path, "unclosed path parameter"))?;
        let name = &tail[..end];
        if name.is_empty() || name.contains('{') || Ident::parse_any.parse_str(name).is_err() {
            return Err(syn::Error::new_spanned(
                path,
                "path parameter must be a field identifier",
            ));
        }
        parts.push(PathPart::Parameter(name.to_owned()));
        tail = &tail[end + 1..];
    }
    if tail.contains('}') {
        return Err(syn::Error::new_spanned(
            path,
            "unmatched closing path brace",
        ));
    }
    parts.push(PathPart::Literal(LitStr::new(tail, path.span())));
    for part in &parts {
        let PathPart::Literal(literal) = part else {
            continue;
        };
        let value = literal.value();
        let bytes = value.as_bytes();
        if bytes.iter().enumerate().any(|(index, byte)| {
            (!byte.is_ascii_alphanumeric() && !b"-._~!$&'()*+,;=:@/%".contains(byte))
                || (*byte == b'%'
                    && (!bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
                        || !bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit)))
        }) {
            return Err(syn::Error::new_spanned(path, "invalid REST path literal"));
        }
    }
    Ok(parts)
}

fn bind_path(
    parts: Vec<PathPart>,
    parameters: &BTreeMap<String, Ident>,
    span: Span,
    path_ident: &Ident,
    encode_ident: &Ident,
) -> syn::Result<Vec<TokenStream>> {
    let mut used = BTreeSet::new();
    let mut statements = Vec::new();
    for part in parts {
        match part {
            PathPart::Literal(value) => statements.push(quote!(#path_ident.push_str(#value);)),
            PathPart::Parameter(name) => {
                if !used.insert(name.clone()) {
                    return Err(syn::Error::new(
                        span,
                        "path parameters must appear exactly once",
                    ));
                }
                let ident = parameters.get(&name).ok_or_else(|| {
                    syn::Error::new(
                        span,
                        format!("path parameter {{{name}}} has no matching #[path_param] field"),
                    )
                })?;
                statements.push(quote! {
                    #encode_ident(&mut #path_ident, &::std::string::ToString::to_string(&self.#ident));
                });
            }
        }
    }
    for (name, ident) in parameters {
        if !used.contains(name) {
            return Err(syn::Error::new_spanned(
                ident,
                "path parameter field has no matching placeholder",
            ));
        }
    }
    Ok(statements)
}

fn encoder(generics: &syn::Generics, encode_ident: &Ident) -> TokenStream {
    let output_ident = fresh_ident(generics, "output");
    let value_ident = fresh_ident(generics, "value");
    let byte_ident = fresh_ident(generics, "byte");
    let hex_ident = fresh_ident(generics, "HEX");
    quote! {
        fn #encode_ident(#output_ident: &mut ::std::string::String, #value_ident: &str) {
            const #hex_ident: &[u8; 16] = b"0123456789ABCDEF";
            for #byte_ident in #value_ident.bytes() {
                if #byte_ident.is_ascii_alphanumeric() || ::core::matches!(#byte_ident, b'-' | b'.' | b'_' | b'~') {
                    #output_ident.push(::core::primitive::char::from(#byte_ident));
                } else {
                    #output_ident.push('%');
                    #output_ident.push(::core::primitive::char::from(#hex_ident[::core::primitive::usize::from(#byte_ident >> 4)]));
                    #output_ident.push(::core::primitive::char::from(#hex_ident[::core::primitive::usize::from(#byte_ident & 15)]));
                }
            }
        }
    }
}

fn valid_header_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn fresh_ident(generics: &syn::Generics, base: &str) -> Ident {
    let mut name = base.to_owned();
    while generics
        .const_params()
        .any(|parameter| parameter.ident.unraw() == name)
    {
        name.push('_');
    }
    Ident::new(&name, Span::mixed_site())
}

#[cfg(test)]
mod tests {
    use super::expand;

    #[test]
    fn generates_valid_syntax_for_named_optional_and_generic_fields() -> syn::Result<()> {
        let input = syn::parse_str(
            r#"
            #[rest(method = "POST", path = "/items/{type}")]
            struct Create<T> {
                #[path_param]
                r#type: T,
                #[query(name = "filter name")]
                filter: Option<String>,
                #[header(name = "x-token")]
                token: Option<String>,
                #[body]
                payload: Vec<u8>,
            }
            "#,
        )?;
        let generated = expand(input)?;
        let _: syn::File = syn::parse2(generated)?;
        Ok(())
    }

    #[test]
    fn rejects_invalid_templates_and_conflicting_placements() -> syn::Result<()> {
        for (source, diagnostic) in [
            (
                r#"#[rest(method = "GET", path = "/%GG")] struct A {}"#,
                "invalid REST path literal",
            ),
            (
                r#"#[rest(method = "GET", path = "/{id}")] struct A { id: u64 }"#,
                "no matching #[path_param] field",
            ),
            (
                r#"#[rest(method = "GET", path = "/")] struct A { #[path_param] id: u64 }"#,
                "no matching placeholder",
            ),
            (
                r#"#[rest(method = "GET", path = "/{id}/{id}")] struct A { #[path_param] id: u64 }"#,
                "exactly once",
            ),
            (
                r#"#[rest(method = "GET", path = "/{id}")] struct A { #[path_param] id: Option<u64> }"#,
                "cannot be optional",
            ),
            (
                r#"#[rest(method = "FETCH", path = "/")] struct A {}"#,
                "unsupported HTTP method",
            ),
            (
                r#"#[rest(method = "GET", path = "/{id")] struct A { #[path_param] id: u64 }"#,
                "unclosed path parameter",
            ),
            (
                r#"#[rest(method = "POST", path = "/")] struct A { #[body] a: Vec<u8>, #[body] b: Vec<u8> }"#,
                "only one body",
            ),
            (
                r#"#[rest(method = "GET", path = "/")] struct A { #[query] #[body] a: String }"#,
                "only one REST placement",
            ),
        ] {
            let input = syn::parse_str(source)?;
            let error = match expand(input) {
                Err(error) => error,
                Ok(_) => panic!("invalid declaration accepted: {source}"),
            };
            assert!(error.to_string().contains(diagnostic), "{error}");
        }
        Ok(())
    }
}
