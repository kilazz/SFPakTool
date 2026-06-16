//build.rs

fn main() {
    slint_build::compile("ui/app.slint").unwrap();
}
