use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use byteorder::{BigEndian, ByteOrder};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use crate::{
    ldap_attribute::{LdapAttribute, LdapValue},
    ldap_operation::LdapOperation,
    ldap_result::LdapResult,
    utils,
};

pub struct Server {}

impl Server {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn start_listening(self) -> std::io::Result<()> {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 389);
        let listener = TcpListener::bind(address).await?;

        println!("Listening on {}", address);

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

                println!("Got {} bytes", n);

                // just assuming this is a bind request for testing...
                let request_packet = LdapAttribute::parse(&buf).unwrap();

                let message_id = match request_packet.value {
                    LdapValue::Primitive(_) => todo!(),
                    LdapValue::Constructed(attributes) => {
                        match attributes.first().unwrap().value.clone() {
                            LdapValue::Primitive(value) => value,
                            LdapValue::Constructed(_) => todo!(),
                        }
                    }
                };

                println!("messageid: {:?}", message_id);

                let foo = utils::bytes_to_i32(&message_id);
                println!("got messageid {}", foo);

                let bind_response_attribute = LdapAttribute::new_result_attribute(
                    LdapOperation::BindResponse,
                    LdapResult::Success,
                );

                let bind_response_packet =
                    LdapAttribute::new_packet(1, vec![bind_response_attribute]);

                let response_bytes = bind_response_packet.get_bytes();

                println!("response bytes: {:?}", response_bytes);

                socket
                    .write_all(&response_bytes)
                    .await
                    .expect("failed to write data to socket");

                socket.flush().await.expect("hu?");
            });
        }
    }
}
