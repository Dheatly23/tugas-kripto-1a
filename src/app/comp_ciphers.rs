use js_sys::Uint8Array;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{HtmlInputElement, HtmlTextAreaElement};
use yew::prelude::*;

use crate::ciphers::*;
use crate::parsers::{mat3x3, trimmed};

#[derive(Properties, PartialEq)]
pub struct CipherBoxProps {
    encryptor: Callback<(), Result<Box<dyn Encryptor>, AttrValue>>,
    decryptor: Callback<(), Result<Box<dyn Decryptor>, AttrValue>>,

    pub children: Children,
}

#[function_component(CipherBox)]
pub fn cipher_box(props: &CipherBoxProps) -> Html {
    fn encrypt(
        mut e: Box<dyn Encryptor>,
        plain: impl IntoIterator<Item = u8>,
    ) -> Result<Vec<u8>, ()> {
        let mut cipher = Vec::new();
        let mut err_happen = false;

        for b in plain {
            if let Ok(s) = e.encrypt_byte(b) {
                cipher.extend_from_slice(s);
            } else {
                err_happen = true;
                break;
            }
        }

        if !err_happen {
            if let Ok(v) = e.encrypt_finish() {
                cipher.extend_from_slice(&v);
            } else {
                err_happen = true;
            }
        }

        if err_happen {
            Err(())
        } else {
            Ok(cipher)
        }
    }

    fn decrypt(
        mut d: Box<dyn Decryptor>,
        cipher: impl IntoIterator<Item = u8>,
    ) -> Result<Vec<u8>, ()> {
        let mut plain = Vec::new();
        let mut err_happen = false;

        for b in cipher {
            if let Ok(s) = d.decrypt_byte(b) {
                plain.extend_from_slice(s);
            } else {
                err_happen = true;
                break;
            }
        }

        if !err_happen {
            if let Ok(v) = d.decrypt_finish() {
                plain.extend_from_slice(&v);
            } else {
                err_happen = true;
            }
        }

        if err_happen {
            Err(())
        } else {
            Ok(plain)
        }
    }

    let file_input = use_node_ref();
    let textbox = use_node_ref();
    let output = use_node_ref();

    let err_happened = use_state_eq(|| false);

    let encrypt_ = {
        let textbox = textbox.clone();
        let output = output.clone();
        let err_happened = err_happened.setter();

        let encryptor = props.encryptor.clone();

        Callback::from(move |_| {
            if let (Some(textbox), Some(output)) = (
                textbox.cast::<HtmlTextAreaElement>(),
                output.cast::<HtmlTextAreaElement>(),
            ) {
                let e = match encryptor.emit(()) {
                    Ok(v) => v,
                    Err(e) => {
                        err_happened.set(true);
                        output.set_value(&format!("Error, {}", e));
                        return;
                    }
                };

                let plain = textbox.value();
                let cipher = encrypt(e, plain.chars().map(|c| c as _));

                err_happened.set(cipher.is_err());
                match cipher {
                    Ok(v) => output.set_value(&String::from_iter(v.into_iter().map(char::from))),
                    Err(_) => output.set_value("Error, cannot encrypt!"),
                }
            }
        })
    };

    let decrypt_ = {
        let textbox = textbox.clone();
        let output = output.clone();
        let err_happened = err_happened.setter();

        let decryptor = props.decryptor.clone();

        Callback::from(move |_| {
            if let (Some(textbox), Some(output)) = (
                textbox.cast::<HtmlTextAreaElement>(),
                output.cast::<HtmlTextAreaElement>(),
            ) {
                let d = match decryptor.emit(()) {
                    Ok(v) => v,
                    Err(e) => {
                        err_happened.set(true);
                        output.set_value(&format!("Error, {}", e));
                        return;
                    }
                };

                let cipher = textbox.value();
                let plain = decrypt(d, cipher.chars().map(|c| c as _));

                err_happened.set(plain.is_err());
                match plain {
                    Ok(v) => output.set_value(&String::from_iter(v.into_iter().map(char::from))),
                    Err(_) => output.set_value("Error, cannot decrypt!"),
                }
            }
        })
    };

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Operator {
        Encrypt,
        Decrypt,
    }

    let operator = use_state_eq(|| Operator::Encrypt);

    let encrypt_file = {
        let file_input = file_input.clone();
        let operator = operator.clone();

        Callback::from(move |_| {
            if let Some(file_input) = file_input.cast::<HtmlInputElement>() {
                operator.set(Operator::Encrypt);
                let file_input = file_input.clone();
                spawn_local(async move { file_input.click() });
            }
        })
    };

    let decrypt_file = {
        let file_input = file_input.clone();
        let operator = operator.clone();

        Callback::from(move |_| {
            if let Some(file_input) = file_input.cast::<HtmlInputElement>() {
                operator.set(Operator::Decrypt);
                let file_input = file_input.clone();
                spawn_local(async move { file_input.click() });
            }
        })
    };

    let execute_file = {
        let file_input = file_input.clone();
        let textbox = textbox.clone();
        let output = output.clone();
        let err_happened = err_happened.setter();

        let encryptor = props.encryptor.clone();
        let decryptor = props.decryptor.clone();

        let operator = operator.clone();

        use_callback(
            move |_, operator| {
                let operator = **operator;

                let (Some(file_input), Some(textbox), Some(output)) = (
                    file_input.cast::<HtmlInputElement>(),
                    textbox.cast::<HtmlTextAreaElement>(),
                    output.cast::<HtmlTextAreaElement>(),
                ) else {return};

                let f = match file_input.files() {
                    Some(files) => match files.get(0) {
                        Some(f) => f,
                        None => return,
                    },
                    None => return,
                };

                let encryptor = encryptor.clone();
                let decryptor = decryptor.clone();
                let err_happened = err_happened.clone();

                spawn_local(async move {
                    let data = match JsFuture::from(f.array_buffer()).await {
                        Ok(v) => Uint8Array::new(&v).to_vec(),
                        Err(e) => {
                            web_sys::console::log_1(&e);
                            return;
                        }
                    };

                    textbox.set_value(&String::from_iter(data.iter().map(|&b| b as char)));

                    let out = match operator {
                        Operator::Encrypt => encrypt(
                            match encryptor.emit(()) {
                                Ok(v) => v,
                                Err(e) => {
                                    err_happened.set(true);
                                    output.set_value(&format!("Error, {}", e));
                                    return;
                                }
                            },
                            data.into_iter(),
                        ),
                        Operator::Decrypt => decrypt(
                            match decryptor.emit(()) {
                                Ok(v) => v,
                                Err(e) => {
                                    err_happened.set(true);
                                    output.set_value(&format!("Error, {}", e));
                                    return;
                                }
                            },
                            data.into_iter(),
                        ),
                    };

                    err_happened.set(out.is_err());
                    if let Ok(v) = out {
                        output.set_value(&String::from_iter(v.iter().map(|&b| b as char)));
                    } else {
                        output.set_value("Error processing");
                    }
                });
            },
            operator,
        )
    };

    html! {
        <div class="cipher_box">
            <div class="key_container">
                { for props.children.iter() }
            </div>
            <textarea ref={textbox} cols=80 rows=10/>
            <textarea ref={output}
                class={ classes!(if *err_happened { Some("error") } else { None } ) }
                readonly=true
                cols=80 rows=10
                style="resize: none;"
            />
            <div class="action_container">
                <button onclick={encrypt_}> { "Encrypt" } </button>
                <button onclick={decrypt_}> { "Decrypt" } </button>
                <button onclick={encrypt_file}> { "Encrypt File" } </button>
                <button onclick={decrypt_file}> { "Decrypt File" } </button>
                <input ref={file_input} type="file" hidden=true onchange={execute_file}/>
            </div>
        </div>
    }
}

#[function_component(CipherVigenere)]
pub fn cipher_vigenere() -> Html {
    fn f(input: &NodeRef) -> Result<impl Encryptor + Decryptor, AttrValue> {
        let key = if let Some(input) = input.cast::<HtmlInputElement>() {
            input.value()
        } else {
            return Err(AttrValue::from("internal error"));
        };

        Ok(<_ as Encryptor>::filter(
            Vignere::new(key.as_bytes())?,
            |b| matches!(b as char, 'A'..='Z' | 'a'..='z'),
        ))
    }

    let input = use_node_ref();

    let cb_e = {
        let input = input.clone();
        Callback::from(move |()| Ok(Box::new(f(&input)?) as _))
    };
    let cb_d = {
        let input = input.clone();
        Callback::from(move |()| Ok(Box::new(f(&input)?) as _))
    };

    html! {
        <CipherBox encryptor={ cb_e } decryptor={ cb_d }>
            <label> { "Key:" } </label>
            <input ref={ input } />
        </CipherBox>
    }
}

#[function_component(CipherVigenere256)]
pub fn cipher_vigenere256() -> Html {
    fn f(input: &NodeRef) -> Result<impl Encryptor + Decryptor, AttrValue> {
        let key = if let Some(input) = input.cast::<HtmlInputElement>() {
            input.value()
        } else {
            return Err(AttrValue::from("internal error"));
        };

        Ok(Vignere256::new(key.as_bytes())?)
    }

    let input = use_node_ref();

    let cb_e = {
        let input = input.clone();
        Callback::from(move |()| Ok(Box::new(f(&input)?) as _))
    };
    let cb_d = {
        let input = input.clone();
        Callback::from(move |()| Ok(Box::new(f(&input)?) as _))
    };

    html! {
        <CipherBox encryptor={ cb_e } decryptor={ cb_d }>
            <label> { "Key:" } </label>
            <input ref={ input } />
        </CipherBox>
    }
}

#[function_component(CipherVigenereAutokey)]
pub fn cipher_vigenere_autokey() -> Html {
    fn f(input: &NodeRef) -> Result<impl Encryptor + Decryptor, AttrValue> {
        let key = if let Some(input) = input.cast::<HtmlInputElement>() {
            input.value()
        } else {
            return Err(AttrValue::from("internal error"));
        };

        Ok(<_ as Encryptor>::filter(
            VignereAutokey::new(key.as_bytes())?,
            |b| matches!(b as char, 'A'..='Z' | 'a'..='z'),
        ))
    }

    let input = use_node_ref();

    let cb_e = {
        let input = input.clone();
        Callback::from(move |()| Ok(Box::new(f(&input)?) as _))
    };
    let cb_d = {
        let input = input.clone();
        Callback::from(move |()| Ok(Box::new(f(&input)?) as _))
    };

    html! {
        <CipherBox encryptor={ cb_e } decryptor={ cb_d }>
            <label> { "Key:" } </label>
            <input ref={ input } />
        </CipherBox>
    }
}

#[function_component(CipherPlayfair)]
pub fn cipher_playfair() -> Html {
    fn f(input: &NodeRef) -> Result<impl Encryptor + Decryptor, AttrValue> {
        let key = if let Some(input) = input.cast::<HtmlInputElement>() {
            input.value()
        } else {
            return Err(AttrValue::from("internal error"));
        };

        Ok(<_ as Encryptor>::filter(
            Playfair::new(key.as_bytes())?,
            |b| matches!(b as char, 'A'..='Z' | 'a'..='z'),
        ))
    }

    let input = use_node_ref();

    let cb_e = {
        let input = input.clone();
        Callback::from(move |()| Ok(Box::new(f(&input)?) as _))
    };
    let cb_d = {
        let input = input.clone();
        Callback::from(move |()| Ok(Box::new(f(&input)?) as _))
    };

    html! {
        <CipherBox encryptor={ cb_e } decryptor={ cb_d }>
            <label> { "Key:" } </label>
            <input ref={ input } />
        </CipherBox>
    }
}

#[function_component(CipherAffine)]
pub fn cipher_affine() -> Html {
    fn f(m: &NodeRef, n: &NodeRef) -> Result<impl Encryptor + Decryptor, AttrValue> {
        let (m, n) = if let (Some(m), Some(n)) =
            (m.cast::<HtmlInputElement>(), n.cast::<HtmlInputElement>())
        {
            match u8::from_str_radix(m.value().trim(), 10)
                .and_then(|m| Ok((m, u8::from_str_radix(n.value().trim(), 10)?)))
            {
                Ok(v) => v,
                Err(e) => return Err(<_>::from(e.to_string())),
            }
        } else {
            return Err(AttrValue::from("internal error"));
        };

        Ok(<_ as Encryptor>::filter(
            Affine::new(m, n)?,
            |b| matches!(b as char, 'A'..='Z' | 'a'..='z'),
        ))
    }

    let input_m = use_node_ref();
    let input_n = use_node_ref();

    let cb_e = {
        let input_m = input_m.clone();
        let input_n = input_n.clone();
        Callback::from(move |()| Ok(Box::new(f(&input_m, &input_n)?) as _))
    };
    let cb_d = {
        let input_m = input_m.clone();
        let input_n = input_n.clone();
        Callback::from(move |()| Ok(Box::new(f(&input_m, &input_n)?) as _))
    };

    html! {
        <CipherBox encryptor={ cb_e } decryptor={ cb_d }>
            <label> { "M:" } </label>
            <input ref={ input_m } type="number" min="1" max="25" value="1" />
            <label> { "N:" } </label>
            <input ref={ input_n } type="number" min="0" max="25" value="0" />
        </CipherBox>
    }
}

#[function_component(CipherHill)]
pub fn cipher_hill() -> Html {
    fn f(input: &NodeRef) -> Result<impl Encryptor + Decryptor, AttrValue> {
        let key;
        if let Some(input) = input.cast::<HtmlInputElement>() {
            let s = input.value();
            if let Ok((_, v)) = trimmed(mat3x3)(&s) {
                key = v;
            } else {
                return Err(AttrValue::from("cannot convert key"));
            }
            drop(s);
        } else {
            return Err(AttrValue::from("internal error"));
        }

        Ok(<_ as Encryptor>::filter(
            Hill::new(key)?,
            |b| matches!(b as char, 'A'..='Z' | 'a'..='z'),
        ))
    }

    let input = use_node_ref();

    let cb_e = {
        let input = input.clone();
        Callback::from(move |()| Ok(Box::new(f(&input)?) as _))
    };
    let cb_d = {
        let input = input.clone();
        Callback::from(move |()| Ok(Box::new(f(&input)?) as _))
    };

    html! {
        <CipherBox encryptor={ cb_e } decryptor={ cb_d }>
            <label> { "Matrix 3x3:" } </label>
            <input ref={ input } />
            <label style="grid-column: 1 / -1;"> { "Eg: 17 17 5 21 18 21 2 2 19" } </label>
        </CipherBox>
    }
}
