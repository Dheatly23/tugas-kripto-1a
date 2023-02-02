mod app;
mod ciphers;
mod parsers;
mod util;

use app::App;

fn main() {
    yew::Renderer::<App>::new().render();
}
