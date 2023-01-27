mod app;
mod ciphers;

use app::App;

fn main() {
    yew::Renderer::<App>::new().render();
}
