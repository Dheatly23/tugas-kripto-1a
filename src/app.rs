use js_sys::Uint8Array;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{HtmlInputElement, HtmlTextAreaElement};
use yew::prelude::*;

use crate::ciphers::*;

#[derive(Properties, PartialEq)]
pub struct TitleBarProps {
    title: AttrValue,
}

#[function_component(TitleBar)]
pub fn title_bar(props: &TitleBarProps) -> Html {
    html!(
        <h1> {props.title.clone()} </h1>
    )
}

#[derive(Properties, PartialEq)]
pub struct TabbedDialogProps {
    tabs: Vec<AttrValue>,
    cb: Callback<Option<usize>, Html>,
}

#[function_component(TabbedDialogue)]
pub fn tabbed_dialog(props: &TabbedDialogProps) -> Html {
    let selected_tab = use_state_eq(|| None);

    let tabs: Vec<_> = props
        .tabs
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let selected =
                selected_tab.and_then(|j| if i == j { Some("selected_tab") } else { None });

            let selected_tab = selected_tab.clone();
            let on_click = Callback::from(move |_| selected_tab.set(Some(i)));

            html! {
                <button onclick={ on_click } class={ classes!(selected) }>
                    { v }
                </button>
            }
        })
        .collect();

    let body = props.cb.emit(*selected_tab);

    html! {
        <div class="tabbed_dialog">
            <div class="header">
                { tabs }
            </div>
            <div class="tab">
                { body }
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct CipherBoxProps {
    encryptor: Callback<String, Box<dyn Encryptor>>,
    decryptor: Callback<String, Box<dyn Decryptor>>,
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
    let input = use_node_ref();
    let textbox = use_node_ref();
    let output = use_node_ref();

    let err_happened = use_state_eq(|| false);

    let encrypt_ = {
        let input = input.clone();
        let textbox = textbox.clone();
        let output = output.clone();
        let err_happened = err_happened.setter();

        let encryptor = props.encryptor.clone();

        Callback::from(move |_| {
            if let (Some(input), Some(textbox), Some(output)) = (
                input.cast::<HtmlInputElement>(),
                textbox.cast::<HtmlTextAreaElement>(),
                output.cast::<HtmlTextAreaElement>(),
            ) {
                let key = input.value();
                let e = encryptor.emit(key);

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
        let input = input.clone();
        let textbox = textbox.clone();
        let output = output.clone();
        let err_happened = err_happened.setter();

        let decryptor = props.decryptor.clone();

        Callback::from(move |_| {
            if let (Some(input), Some(textbox), Some(output)) = (
                input.cast::<HtmlInputElement>(),
                textbox.cast::<HtmlTextAreaElement>(),
                output.cast::<HtmlTextAreaElement>(),
            ) {
                let key = input.value();
                let d = decryptor.emit(key);

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
        let input = input.clone();
        let textbox = textbox.clone();
        let output = output.clone();
        let err_happened = err_happened.setter();

        let encryptor = props.encryptor.clone();
        let decryptor = props.decryptor.clone();

        let operator = operator.clone();

        use_callback(
            move |_, operator| {
                let operator = **operator;

                let (Some(file_input), Some(input), Some(textbox), Some(output)) = (
                    file_input.cast::<HtmlInputElement>(),
                    input.cast::<HtmlInputElement>(),
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

                let key = input.value();

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
                        Operator::Encrypt => encrypt(encryptor.emit(key), data.into_iter()),
                        Operator::Decrypt => decrypt(decryptor.emit(key), data.into_iter()),
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
                <label> { "Key:" } </label>
                <input ref={input} />
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

#[function_component(App)]
pub fn app() -> Html {
    let tabs: Vec<_> = ["Vigenere", "Vigenere (Autokey)", "Vigenere (8-bit)"]
        .into_iter()
        .map(AttrValue::from)
        .collect();
    let tab_body = Callback::from(|v: Option<usize>| -> Html {
        let (v, cb_e, cb_d): (
            _,
            Callback<String, Box<dyn Encryptor>>,
            Callback<String, Box<dyn Decryptor>>,
        ) = match v {
            Some(v @ 2) => {
                fn f(key: String) -> impl Encryptor + Decryptor {
                    Vignere256::new(key.as_bytes())
                }

                (
                    v,
                    Callback::from(|k| Box::new(f(k)) as _),
                    Callback::from(|k| Box::new(f(k)) as _),
                )
            }
            Some(v @ 1) => {
                fn f(key: String) -> impl Encryptor + Decryptor {
                    <_ as Encryptor>::filter(
                        VignereAutokey::new(key.as_bytes()),
                        |b| matches!(b as char, 'A'..='Z' | 'a'..='z'),
                    )
                }

                (
                    v,
                    Callback::from(|k| Box::new(f(k)) as _),
                    Callback::from(|k| Box::new(f(k)) as _),
                )
            }
            _ => {
                fn f(key: String) -> impl Encryptor + Decryptor {
                    <_ as Encryptor>::filter(
                        Vignere::new(key.as_bytes()),
                        |b| matches!(b as char, 'A'..='Z' | 'a'..='z'),
                    )
                }

                (
                    0,
                    Callback::from(|k| Box::new(f(k)) as _),
                    Callback::from(|k| Box::new(f(k)) as _),
                )
            }
        };

        html! {
            <CipherBox
                key={ v }
                encryptor={ cb_e }
                decryptor={ cb_d }
            />
        }
    });

    html! {
        <main>
            <TitleBar title="Title Bar" />
            <TabbedDialogue
                tabs={ tabs }
                cb={ tab_body }
            />
        </main>
    }
}
