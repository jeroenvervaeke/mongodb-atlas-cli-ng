use mongodb_atlas_cli::{
    config,
    secrets::{ProfileName, get_secret_store},
};

pub fn main() {
    // Load the config
    let config = config::load_config(Some("default")).unwrap();
    println!("{:#?}", config);

    // Get the authentication type used in the config
    let Some(auth_type) = config.auth_type else {
        eprintln!("Authentication type not set in config, exiting");
        return;
    };

    // Get the secret store
    let secret_store = get_secret_store().unwrap();
    let profile = ProfileName::new("default").unwrap();
    let secret = secret_store.get(&profile, auth_type).unwrap().unwrap();

    // Print the secret (secret fields are redacted in Debug output)
    println!("{:#?}", secret);
}
