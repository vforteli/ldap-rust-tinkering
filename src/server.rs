use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use crate::ldap_attribute::LdapAttribute;

pub struct Server {}

impl Server {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn start_listening(self) -> std::io::Result<()> {
        let listener = TcpListener::bind("0.0.0.0:389").await?;

        loop {
            let (mut socket, _) = listener.accept().await?;
            println!("Got client from {:?}", socket.peer_addr());

            // todo threadpool
            tokio::spawn(async move {
                let mut buf = vec![0; 1024 * 10];

                // testing...
                // loop {
                let n = socket
                    .read(&mut buf)
                    .await
                    .expect("failed to read data from socket");

                if n == 0 {
                    return;
                }

                let _packet = LdapAttribute::parse(&buf);

                let response = "lulz".as_bytes();
                socket
                    .write_all(response)
                    .await
                    .expect("failed to write data to socket");
                // }
            });
        }
    }
}
