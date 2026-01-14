use mongodb_atlas_cli::client::make_request;

#[tokio::main]
async fn main() {

    make_request().await;

}