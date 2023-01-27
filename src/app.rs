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
            let selected_tab = selected_tab.clone();
            let on_click = Callback::from(move |_| selected_tab.set(Some(i)));
            html! {
                <button onclick={on_click}>
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

    let input = use_node_ref();
    let textbox = use_node_ref();
    let output = use_node_ref();

    let err_happened = use_state_eq(|| false);

    let encrypt = {
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

    let decrypt = {
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
                <button onclick={encrypt}> { "Encrypt" } </button>
                <button onclick={decrypt}> { "Decrypt" } </button>
            </div>
        </div>
    }
}

#[function_component(App)]
pub fn app() -> Html {
    let tabs: Vec<_> = ["Tab 1", "Tab 2", "Tab 3"]
        .into_iter()
        .map(AttrValue::from)
        .collect();
    let tab_body = Callback::from(|v: Option<usize>| -> Html {
        let (v, cb_e, cb_d): (
            _,
            Callback<String, Box<dyn Encryptor>>,
            Callback<String, Box<dyn Decryptor>>,
        ) = match v {
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
