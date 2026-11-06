use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    LitStr, Token,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
};

struct Pair {
    name: LitStr,
    value: LitStr,
}

impl Parse for Pair {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let name = input.parse()?;
        input.parse::<Token![=>]>()?;
        let value = input.parse()?;
        Ok(Self { name, value })
    }
}

struct Pairs(Punctuated<Pair, Token![,]>);

impl Parse for Pairs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        Ok(Self(Punctuated::parse_terminated(input)?))
    }
}

pub(crate) fn validate_name(name: &LitStr, pseudo: bool) -> syn::Result<()> {
    let value = name.value();
    let token = if pseudo {
        value.strip_prefix(':').unwrap_or(&value)
    } else {
        &value
    };
    if token.is_empty()
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    {
        return Err(syn::Error::new(name.span(), "invalid HTTP header name"));
    }
    if pseudo && value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(syn::Error::new(
            name.span(),
            "HTTP/2 header names must be lowercase",
        ));
    }
    Ok(())
}

pub(crate) fn validate_value(value: &LitStr) -> syn::Result<()> {
    if value.value().bytes().any(|byte| {
        byte == b'\r' || byte == b'\n' || byte == 0x7f || (byte < 0x20 && byte != b'\t')
    }) {
        return Err(syn::Error::new(
            value.span(),
            "HTTP header values cannot contain line breaks or control bytes",
        ));
    }
    Ok(())
}

pub(crate) fn expand(input: TokenStream, pseudo: bool) -> syn::Result<TokenStream> {
    let Pairs(pairs) = syn::parse2(input)?;
    for pair in &pairs {
        validate_name(&pair.name, pseudo)?;
        validate_value(&pair.value)?;
    }
    let names: Vec<_> = pairs.iter().map(|pair| &pair.name).collect();
    let values: Vec<_> = pairs.iter().map(|pair| &pair.value).collect();
    if pseudo {
        Ok(quote! {{
            let __nexora_pairs: ::std::vec::Vec<(
                ::std::string::String,
                ::std::string::String,
            )> = ::std::vec![#(
                (::std::string::String::from(#names), ::std::string::String::from(#values))
            ),*];
            __nexora_pairs
        }})
    } else {
        let capacity = pairs.len();
        Ok(quote! {{
            let mut __nexora_headers = ::nexora_proto::Headers::with_capacity(#capacity);
            #(__nexora_headers.append(#names, #values);)*
            __nexora_headers
        }})
    }
}

#[cfg(test)]
mod tests {
    use quote::quote;

    use super::expand;

    #[test]
    fn rejects_header_injection_and_invalid_names() {
        for input in [
            quote!("x\r\ny" => "value"),
            quote!("x-name" => "value\r\nInjected: yes"),
            quote!("x-name" => "\0"),
            quote!("" => "value"),
            quote!(":path" => "/"),
        ] {
            assert!(expand(input, false).is_err());
        }
    }

    #[test]
    fn validates_http2_names_and_accepts_repeated_headers() {
        assert!(expand(quote!(":method" => "GET", ":path" => "/"), true).is_ok());
        assert!(expand(quote!("X-name" => "v"), true).is_err());
        assert!(expand(quote!("::method" => "GET"), true).is_err());
        assert!(expand(quote!("set-cookie" => "a", "set-cookie" => "b",), false).is_ok());
        assert!(expand(quote!(), true).is_ok());
    }
}
