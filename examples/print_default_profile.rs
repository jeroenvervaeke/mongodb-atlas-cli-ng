use atlas_cli::config;

pub fn main() {
    let config = config::load_config(Some("default")).unwrap();
    println!("{:#?}", config);
}
