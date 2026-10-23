use std::collections::BTreeSet;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    Attribute, FnArg, GenericArgument, ImplItem, ImplItemFn, ItemImpl, LitStr, Meta, PathArguments,
    ReturnType, Type, ext::IdentExt, parse_quote, punctuated::Punctuated, spanned::Spanned,
};

struct Route {
    method: syn::Ident,
    path: LitStr,
    segments: Vec<Option<String>>,
    handler: syn::Ident,
    deferred: bool,
    conditions: Vec<Attribute>,
}

pub(crate) fn expand(mut input: ItemImpl) -> syn::Result<TokenStream> {
    if input.trait_.is_some() {
        return Err(syn::Error::new_spanned(
            &input,
            "http_service requires an inherent impl",
        ));
    }
    let ctx_ident = fresh_ident(&input.generics, "ctx");
    let req_ident = fresh_ident(&input.generics, "req");
    let responder_ident = fresh_ident(&input.generics, "responder");
    let response_ident = fresh_ident(&input.generics, "response");
    let status_ident = fresh_ident(&input.generics, "status");
    let path_matched_ident = fresh_ident(&input.generics, "__nexora_path_matched");
    let segments_ident = fresh_ident(&input.generics, "__nexora_segments");
    let segment_ident = fresh_ident(&input.generics, "segment");
    let mut routes = Vec::new();
    for item in &mut input.items {
        let ImplItem::Fn(function) = item else {
            continue;
        };
        let conditions = conditional_attributes(&function.attrs)?;
        let mut retained = Vec::new();
        for attr in std::mem::take(&mut function.attrs) {
            if let Some((method, path)) = route_attribute(&attr)? {
                let segments = path_segments(&path)?;
                let specificity = segments.iter().filter(|segment| segment.is_none()).count();
                if routes.iter().any(|route: &Route| {
                    route.method == method
                        && route.segments.len() == segments.len()
                        && route.segments.iter().filter(|part| part.is_none()).count()
                            == specificity
                        && route
                            .segments
                            .iter()
                            .zip(&segments)
                            .all(|(left, right)| left.is_none() || right.is_none() || left == right)
                }) {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "duplicate or ambiguous route",
                    ));
                }
                routes.push(Route {
                    method,
                    path,
                    segments,
                    handler: function.sig.ident.clone(),
                    deferred: validate_handler(function)?,
                    conditions: conditions.clone(),
                });
            } else {
                retained.push(attr);
            }
        }
        function.attrs = retained;
    }
    if routes.is_empty() {
        return Err(syn::Error::new_spanned(
            &input,
            "http_service requires at least one route",
        ));
    }
    routes.sort_by_key(|route| route.segments.iter().filter(|part| part.is_none()).count());
    let branches = routes.iter().map(|route| {
        let method = &route.method;
        let conditions = &route.conditions;
        let handler = &route.handler;
        let matches = path_match(route, &req_ident, &segments_ident, &segment_ident);
        let call = if route.deferred {
            quote! { return Self::#handler(self, #ctx_ident, #req_ident, #responder_ident); }
        } else {
            quote! {
                let #response_ident = Self::#handler(self, #ctx_ident, #req_ident)?;
                return #responder_ident.respond(#response_ident);
            }
        };
        quote! {
            #(#conditions)*
            if #matches {
                if #req_ident.method == ::nexora_proto::Method::#method {
                    #call
                }
                #path_matched_ident = true;
            }
        }
    });
    let self_ty = &input.self_ty;
    let conditions = conditional_attributes(&input.attrs)?;
    let (impl_generics, _, where_clause) = input.generics.split_for_impl();
    Ok(quote! {
        #input
        #(#conditions)*
        impl #impl_generics ::nexora::HttpService for #self_ty #where_clause {
            fn call(
                &mut self,
                #ctx_ident: &mut ::nexora::RequestContext,
                #req_ident: ::nexora_proto::Request,
                #responder_ident: ::nexora::Responder,
            ) -> ::nexora::Result<()> {
                #[allow(unused_mut)]
                let mut #path_matched_ident = false;
                #(#branches)*
                let #status_ident = if #path_matched_ident {
                    ::nexora_proto::StatusCode(405)
                } else {
                    ::nexora_proto::StatusCode::NOT_FOUND
                };
                #responder_ident.respond(::nexora_proto::Response::new(#status_ident))
            }
        }
    })
}

fn route_attribute(attr: &Attribute) -> syn::Result<Option<(syn::Ident, LitStr)>> {
    if attr.path().is_ident("ws") {
        return Err(syn::Error::new_spanned(
            attr,
            "WebSocket upgrades require HttpServer::with_websocket_handler; #[ws] has no upgrade \
             factory in the service contract",
        ));
    }
    let aliases = [
        ("get", "GET"),
        ("post", "POST"),
        ("put", "PUT"),
        ("delete", "DELETE"),
        ("head", "HEAD"),
        ("options", "OPTIONS"),
        ("patch", "PATCH"),
        ("connect", "CONNECT"),
        ("trace", "TRACE"),
    ];
    for (alias, method) in aliases {
        if attr.path().is_ident(alias) {
            return Ok(Some((
                method_ident(method, attr.span())?,
                attr.parse_args()?,
            )));
        }
    }
    if !attr.path().is_ident("route") {
        return Ok(None);
    }
    let mut method = None;
    let mut path = None;
    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("method") {
            if method.is_some() {
                return Err(meta.error("duplicate route method"));
            }
            method = Some(meta.value()?.parse::<LitStr>()?);
        } else if meta.path.is_ident("path") {
            if path.is_some() {
                return Err(meta.error("duplicate route path"));
            }
            path = Some(meta.value()?.parse::<LitStr>()?);
        } else {
            return Err(meta.error("expected method or path"));
        }
        Ok(())
    })?;
    let method = method.ok_or_else(|| syn::Error::new_spanned(attr, "route requires method"))?;
    let path = path.ok_or_else(|| syn::Error::new_spanned(attr, "route requires path"))?;
    Ok(Some((method_ident(&method.value(), method.span())?, path)))
}

fn method_ident(method: &str, span: proc_macro2::Span) -> syn::Result<syn::Ident> {
    let name = match method {
        "GET" => "Get",
        "POST" => "Post",
        "PUT" => "Put",
        "DELETE" => "Delete",
        "HEAD" => "Head",
        "OPTIONS" => "Options",
        "PATCH" => "Patch",
        "CONNECT" => "Connect",
        "TRACE" => "Trace",
        _ => {
            return Err(syn::Error::new(
                span,
                "unsupported HTTP method; use an uppercase standard method",
            ));
        }
    };
    Ok(syn::Ident::new(name, span))
}

fn path_segments(path: &LitStr) -> syn::Result<Vec<Option<String>>> {
    let raw = path.value();
    if !raw.starts_with('/')
        || raw.contains(['?', '#'])
        || raw.bytes().any(|byte| byte <= 32 || byte == 127)
    {
        return Err(syn::Error::new_spanned(
            path,
            "route path must be an absolute path without query, fragment, or whitespace",
        ));
    }
    let mut names = BTreeSet::new();
    raw.split('/')
        .map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                let name = &segment[1..segment.len() - 1];
                let valid = !name.is_empty()
                    && name.bytes().enumerate().all(|(index, byte)| {
                        byte == b'_'
                            || byte.is_ascii_alphabetic()
                            || (index > 0 && byte.is_ascii_digit())
                    });
                if !valid || !names.insert(name) {
                    return Err(syn::Error::new_spanned(
                        path,
                        "path placeholders must have distinct identifier names",
                    ));
                }
                Ok(None)
            } else if segment.contains(['{', '}']) {
                Err(syn::Error::new_spanned(
                    path,
                    "path placeholders must occupy a complete path segment",
                ))
            } else {
                let bytes = segment.as_bytes();
                if bytes.iter().enumerate().any(|(index, byte)| {
                    !byte.is_ascii_alphanumeric() && !b"-._~!$&'()*+,;=:@%".contains(byte)
                        || (*byte == b'%'
                            && (!bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
                                || !bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit)))
                }) {
                    return Err(syn::Error::new_spanned(path, "invalid route path literal"));
                }
                Ok(Some(segment.to_owned()))
            }
        })
        .collect()
}

fn path_match(
    route: &Route,
    req_ident: &syn::Ident,
    segments_ident: &syn::Ident,
    segment_ident: &syn::Ident,
) -> TokenStream {
    if route.segments.iter().all(Option::is_some) {
        let path = &route.path;
        return quote! { #req_ident.path() == #path };
    }
    let checks = route.segments.iter().map(|part| match part {
        Some(value) => quote! { #segments_ident.next() == ::core::option::Option::Some(#value) },
        None => quote! { ::core::matches!(#segments_ident.next(), ::core::option::Option::Some(#segment_ident) if !#segment_ident.is_empty()) },
    });
    quote! {{
        let mut #segments_ident = #req_ident.path().split('/');
        #(#checks)&&* && #segments_ident.next().is_none()
    }}
}

fn validate_handler(function: &ImplItemFn) -> syn::Result<bool> {
    let sig = &function.sig;
    if sig.asyncness.is_some()
        || sig.unsafety.is_some()
        || sig.constness.is_some()
        || sig.abi.is_some()
        || !sig.generics.params.is_empty()
        || sig.variadic.is_some()
    {
        return Err(syn::Error::new_spanned(
            sig,
            "route handlers must be ordinary non-generic synchronous methods",
        ));
    }
    let mut args = sig.inputs.iter();
    if !matches!(args.next(), Some(FnArg::Receiver(receiver)) if receiver.reference.is_some() && receiver.mutability.is_some() && receiver.colon_token.is_none())
    {
        return Err(syn::Error::new_spanned(
            sig,
            "route handler requires &mut self",
        ));
    }
    let args: Vec<_> = args.collect();
    if args.len() != 2 && args.len() != 3 {
        return Err(syn::Error::new_spanned(
            sig,
            "expected context, request, and optional responder arguments",
        ));
    }
    let context = argument_type(args[0])?;
    if !matches!(context, Type::Reference(reference) if reference.mutability.is_some() && type_named(&reference.elem, "RequestContext"))
    {
        return Err(syn::Error::new_spanned(
            context,
            "context must be &mut RequestContext",
        ));
    }
    if !type_named(argument_type(args[1])?, "Request") {
        return Err(syn::Error::new_spanned(
            args[1],
            "request must be an owned Request",
        ));
    }
    let deferred = args.len() == 3;
    if deferred && !type_named(argument_type(args[2])?, "Responder") {
        return Err(syn::Error::new_spanned(
            args[2],
            "deferred handler requires an owned Responder",
        ));
    }
    let ReturnType::Type(_, output) = &sig.output else {
        return Err(syn::Error::new_spanned(
            sig,
            "route handler must return Result<Response> or Result<()>",
        ));
    };
    let result = result_value(output).ok_or_else(|| {
        syn::Error::new_spanned(
            output,
            "route handler must return Result<Response> or Result<()>",
        )
    })?;
    if (deferred && !matches!(result, Type::Tuple(tuple) if tuple.elems.is_empty()))
        || (!deferred && !type_named(result, "Response"))
    {
        return Err(syn::Error::new_spanned(
            output,
            "immediate handlers return Result<Response>; deferred handlers return Result<()>",
        ));
    }
    Ok(deferred)
}

fn argument_type(arg: &FnArg) -> syn::Result<&Type> {
    match arg {
        FnArg::Typed(arg) => Ok(&arg.ty),
        FnArg::Receiver(_) => Err(syn::Error::new_spanned(arg, "unexpected receiver argument")),
    }
}

fn type_named(ty: &Type, name: &str) -> bool {
    matches!(ty, Type::Path(path) if path.qself.is_none() && path.path.segments.last().is_some_and(|part| part.ident == name))
}

fn result_value(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else { return None };
    let last = path.path.segments.last()?;
    if last.ident != "Result" {
        return None;
    }
    let PathArguments::AngleBracketed(args) = &last.arguments else {
        return None;
    };
    match args.args.first()? {
        GenericArgument::Type(value) => Some(value),
        _ => None,
    }
}

fn conditional_attributes(attrs: &[Attribute]) -> syn::Result<Vec<Attribute>> {
    fn condition(meta: &Meta) -> syn::Result<Option<Meta>> {
        if meta.path().is_ident("cfg") {
            return Ok(Some(meta.clone()));
        }
        if !meta.path().is_ident("cfg_attr") {
            return Ok(None);
        }
        let Meta::List(list) = meta else {
            return Ok(None);
        };
        let arguments =
            list.parse_args_with(Punctuated::<Meta, syn::Token![,]>::parse_terminated)?;
        let mut arguments = arguments.into_iter();
        let predicate = arguments
            .next()
            .ok_or_else(|| syn::Error::new_spanned(meta, "missing cfg_attr predicate"))?;
        let nested = arguments
            .map(|argument| condition(&argument))
            .collect::<syn::Result<Vec<_>>>()?;
        let nested: Vec<_> = nested.into_iter().flatten().collect();
        Ok((!nested.is_empty()).then(|| parse_quote!(cfg_attr(#predicate, #(#nested),*))))
    }
    attrs
        .iter()
        .filter_map(|attr| match condition(&attr.meta) {
            Ok(Some(meta)) => Some(Ok(parse_quote!(#[#meta]))),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn fresh_ident(generics: &syn::Generics, base: &str) -> syn::Ident {
    let mut name = base.to_owned();
    while generics
        .const_params()
        .any(|parameter| parameter.ident.unraw() == name)
    {
        name.push('_');
    }
    syn::Ident::new(&name, proc_macro2::Span::mixed_site())
}

#[cfg(test)]
mod tests {
    use super::expand;

    #[test]
    fn rejects_overlapping_routes_without_a_specificity_order() -> syn::Result<()> {
        let input = syn::parse_str(
            r#"
            impl Service {
                #[get("/{item}/fixed")]
                fn left(&mut self, _: &mut RequestContext, _: Request) -> Result<Response> {}
                #[get("/fixed/{item}")]
                fn right(&mut self, _: &mut RequestContext, _: Request) -> Result<Response> {}
            }
        "#,
        )?;
        let error = match expand(input) {
            Err(error) => error,
            Ok(_) => panic!("ambiguous route declarations were accepted"),
        };
        assert_eq!(error.to_string(), "duplicate or ambiguous route");
        Ok(())
    }

    #[test]
    fn rejects_non_uri_route_literals() -> syn::Result<()> {
        for path in ["/bad%", "/bad%GG", "/bad\0", "/[bad]"] {
            let path = syn::LitStr::new(path, proc_macro2::Span::call_site());
            let input = syn::parse2(quote::quote! {
                impl Service {
                    #[get(#path)]
                    fn get(&mut self, _: &mut RequestContext, _: Request) -> Result<Response> {}
                }
            })?;
            assert!(expand(input).is_err(), "invalid literal was accepted");
        }
        Ok(())
    }
}
