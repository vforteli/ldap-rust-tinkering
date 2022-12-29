use crate::server::Server;

pub mod ldap_attribute;
pub mod ldap_filter_choice;
pub mod ldap_operation;
pub mod ldap_result;
pub mod server;
pub mod tag;
pub mod tag_class;
pub mod universal_data_type;
pub mod utils;
pub mod ldap_error;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    println!("Starting server...");

    let server = Server::new();
    server.start_listening().await
}
