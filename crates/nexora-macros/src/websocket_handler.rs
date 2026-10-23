use std::collections::BTreeMap;

use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::{
    Attribute, FnArg, GenericArgument, ImplItem, ImplItemFn, ItemImpl, PathArguments, ReturnType,
    Type, ext::IdentExt,
};

pub(crate) fn expand(mut input: ItemImpl) -> syn::Result<TokenStream> {
    if input.trait_.is_some() {
        return Err(syn::Error::new_spanned(
            &input,
            "websocket_handler requires an inherent impl",
        ));
    }
    let events = [
        "on_open",
        "on_message",
        "on_text",
        "on_binary",
        "on_ping",
        "on_pong",
        "on_close",
        "on_error",
    ];
    let mut handlers = BTreeMap::new();
    for item in &mut input.items {
        let ImplItem::Fn(function) = item else {
            continue;
        };
        let mut event = None;
        let mut retained = Vec::new();
        for attr in std::mem::take(&mut function.attrs) {
            let known = events.iter().find(|name| attr.path().is_ident(**name));
            if let Some(name) = known {
                if !matches!(attr.meta, syn::Meta::Path(_)) {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "WebSocket event attributes take no arguments",
                    ));
                }
                if event.replace(*name).is_some() {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "a method can handle only one WebSocket event",
                    ));
                }
            } else {
                retained.push(attr);
            }
        }
        function.attrs = retained;
        let name = function.sig.ident.to_string();
        let event = event.or_else(|| events.iter().copied().find(|event| *event == name));
        if let Some(event) = event {
            validate_handler(function, event)?;
            let handler = (
                function.sig.ident.clone(),
                conditional_attrs(&function.attrs),
            );
            if handlers.insert(event, handler).is_some() {
                return Err(syn::Error::new_spanned(
                    &function.sig,
                    "duplicate WebSocket event handler",
                ));
            }
        }
    }
    if handlers.is_empty() {
        return Err(syn::Error::new_spanned(
            &input,
            "websocket_handler requires at least one event handler",
        ));
    }
    let session = binding(&input, "__nexora_websocket_session");
    let message = binding(&input, "__nexora_websocket_message");
    let payload = binding(&input, "__nexora_websocket_payload");
    let close_value = binding(&input, "__nexora_websocket_close");
    let error_value = binding(&input, "__nexora_websocket_error");
    let open = handlers.get("on_open").map(|(handler, attrs)| {
        quote! {
            #(#attrs)*
            fn on_open(&mut self, #session: &mut ::nexora::WebSocketServerSession) -> ::nexora::Result<()> {
                Self::#handler(self, #session)
            }
        }
    });
    let close = handlers.get("on_close").map(|(handler, attrs)| {
        quote! {
            #(#attrs)*
            fn on_close(
                &mut self,
                #session: &mut ::nexora::WebSocketServerSession,
                #close_value: ::std::option::Option<::nexora_proto::WebSocketCloseFrame>,
            ) -> ::nexora::Result<()> {
                Self::#handler(self, #session, #close_value)
            }
        }
    });
    let error = handlers.get("on_error").map(|(handler, attrs)| quote! {
        #(#attrs)*
        fn on_error(&mut self, #session: &mut ::nexora::WebSocketServerSession, #error_value: &::nexora::Error) {
            Self::#handler(self, #session, #error_value)
        }
    });
    let mut message_arms = Vec::new();
    for (event, variant) in [
        ("on_text", "Text"),
        ("on_binary", "Binary"),
        ("on_ping", "Ping"),
        ("on_pong", "Pong"),
    ] {
        if let Some((handler, attrs)) = handlers.get(event) {
            let variant = syn::Ident::new(variant, handler.span());
            message_arms.push(quote! {
                #(#attrs)*
                ::nexora_proto::WebSocketMessage::#variant(#payload) => Self::#handler(self, #session, #payload),
            });
        }
    }
    let fallback = if let Some((handler, attrs)) = handlers.get("on_message") {
        quote! {
            #(#attrs)*
            #message => Self::#handler(self, #session, #message),
            #[allow(unreachable_patterns)]
            _ => ::std::result::Result::Ok(()),
        }
    } else {
        quote! { _ => ::std::result::Result::Ok(()) }
    };
    let impl_attrs = conditional_attrs(&input.attrs);
    let self_ty = &input.self_ty;
    let (impl_generics, _, where_clause) = input.generics.split_for_impl();
    Ok(quote! {
        #input
        #(#impl_attrs)*
        impl #impl_generics ::nexora::WebSocketUpgradeHandler for #self_ty #where_clause {
            #open
            fn on_message(
                &mut self,
                #session: &mut ::nexora::WebSocketServerSession,
                #message: ::nexora_proto::WebSocketMessage,
            ) -> ::nexora::Result<()> {
                match #message { #(#message_arms)* #fallback }
            }
            #close
            #error
        }
    })
}

fn binding(input: &ItemImpl, base: &str) -> Ident {
    let mut name = base.to_owned();
    while input
        .generics
        .const_params()
        .any(|param| param.ident.unraw() == name)
    {
        name.push('_');
    }
    Ident::new(&name, Span::mixed_site())
}

fn conditional_attrs(attrs: &[Attribute]) -> Vec<Attribute> {
    attrs
        .iter()
        .filter_map(|attr| conditional_meta(&attr.meta))
        .map(|meta| syn::parse_quote!(#[#meta]))
        .collect()
}

fn conditional_meta(meta: &syn::Meta) -> Option<syn::Meta> {
    if meta.path().is_ident("cfg") {
        return Some(meta.clone());
    }
    let syn::Meta::List(list) = meta else {
        return None;
    };
    if !list.path.is_ident("cfg_attr") {
        return None;
    }
    let args = list
        .parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
        .ok()?;
    let mut args = args.iter();
    let predicate = args.next()?;
    let conditional: Vec<_> = args.filter_map(conditional_meta).collect();
    if conditional.is_empty() {
        return None;
    }
    Some(syn::parse_quote!(cfg_attr(#predicate, #(#conditional),*)))
}

fn validate_handler(function: &ImplItemFn, event: &str) -> syn::Result<()> {
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
            "WebSocket handlers must be ordinary non-generic synchronous methods",
        ));
    }
    let mut inputs = sig.inputs.iter();
    if !matches!(inputs.next(), Some(FnArg::Receiver(receiver)) if receiver.reference.is_some() && receiver.mutability.is_some() && receiver.colon_token.is_none())
    {
        return Err(syn::Error::new_spanned(
            sig,
            "WebSocket handler requires &mut self",
        ));
    }
    let args: Vec<_> = inputs.collect();
    let expected = if event == "on_open" { 1 } else { 2 };
    if args.len() != expected {
        return Err(syn::Error::new_spanned(
            sig,
            "WebSocket handler has an invalid argument count",
        ));
    }
    let session = argument_type(args[0])?;
    if !matches!(session, Type::Reference(reference) if reference.mutability.is_some() && type_named(&reference.elem, "WebSocketServerSession"))
    {
        return Err(syn::Error::new_spanned(
            session,
            "session must be &mut WebSocketServerSession",
        ));
    }
    if event != "on_open" {
        let payload = argument_type(args[1])?;
        let valid = match event {
            "on_message" => type_named(payload, "WebSocketMessage"),
            "on_text" => type_named(payload, "String"),
            "on_binary" | "on_ping" | "on_pong" => type_named(payload, "Bytes"),
            "on_close" => option_of(payload, "WebSocketCloseFrame"),
            "on_error" => {
                matches!(payload, Type::Reference(reference) if reference.mutability.is_none() && type_named(&reference.elem, "Error"))
            }
            _ => false,
        };
        if !valid {
            return Err(syn::Error::new_spanned(
                payload,
                format!("invalid payload type for {event}"),
            ));
        }
    }
    if event == "on_error" {
        if !matches!(&sig.output, ReturnType::Default)
            && !matches!(&sig.output, ReturnType::Type(_, ty) if is_unit(ty))
        {
            return Err(syn::Error::new_spanned(
                &sig.output,
                "on_error must return ()",
            ));
        }
    } else if !matches!(&sig.output, ReturnType::Type(_, ty) if result_unit(ty)) {
        return Err(syn::Error::new_spanned(
            &sig.output,
            "WebSocket event handlers must return Result<()>",
        ));
    }
    Ok(())
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

fn option_of(ty: &Type, name: &str) -> bool {
    generic_value(ty, "Option").is_some_and(|ty| type_named(ty, name))
}

fn result_unit(ty: &Type) -> bool {
    generic_value(ty, "Result").is_some_and(is_unit)
}

fn generic_value<'a>(ty: &'a Type, name: &str) -> Option<&'a Type> {
    let Type::Path(path) = ty else { return None };
    let last = path.path.segments.last()?;
    if last.ident != name {
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

fn is_unit(ty: &Type) -> bool {
    matches!(ty, Type::Tuple(tuple) if tuple.elems.is_empty())
}
