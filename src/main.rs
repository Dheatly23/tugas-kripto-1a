mod app;
mod ciphers;
mod parsers;

use app::App;

fn main() {
    yew::Renderer::<App>::new().render();
}
