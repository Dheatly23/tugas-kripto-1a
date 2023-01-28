mod comp_ciphers;

use yew::prelude::*;

use comp_ciphers::*;

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

#[function_component(App)]
pub fn app() -> Html {
    let tabs: Vec<_> = [
        "Vigenere",
        "Vigenere (Autokey)",
        "Vigenere (8-bit)",
        "Playfair",
        "Affine",
        "Hill",
    ]
    .into_iter()
    .map(AttrValue::from)
    .collect();

    let tab_body = Callback::from(|v: Option<usize>| -> Html {
        match v {
            Some(1) => html! {
                <CipherVigenereAutokey key={ 1 } />
            },
            Some(2) => html! {
                <CipherVigenere256 key={ 2 } />
            },
            Some(3) => html! {
                <CipherPlayfair key={ 3 } />
            },
            Some(4) => html! {
                <CipherAffine key={ 4 } />
            },
            Some(5) => html! {
                <CipherHill key={ 5 } />
            },
            _ => html! {
                <CipherVigenere key={ 0 } />
            },
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
