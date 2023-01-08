use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    vec,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use crate::{
    ldap_attribute::{LdapAttribute, LdapValue},
    ldap_error::LdapError,
    ldap_operation::LdapOperation,
    ldap_result::LdapResult,
    tag::Tag,
    universal_data_type::UniversalDataType,
    utils,
};

pub struct Server {}

impl Server {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn start_listening(self, port: u16) -> std::io::Result<()> {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
        let listener = TcpListener::bind(address).await?;

        println!("Listening on {}", address);

        loop {
            let (mut socket, _) = listener.accept().await?;
            println!("Got client from {:?}", socket.peer_addr());

            // todo threadpool
            tokio::spawn(async move {
                let mut buf = vec![0; 1024 * 10];

                // todo uh.. should probably exit this loop at some point...
                loop {
                    let n = socket
                        .read(&mut buf)
                        .await
                        .expect("failed to read data from socket");

                    if n == 0 {
                        println!("{:?} remote closed connection", socket.peer_addr());
                        return;
                    }

                    let length_foo = utils::parse_ber_length_first_byte(buf[1]);
                    println!("length: {:?}", length_foo);

                    let request_packet = LdapAttribute::parse(&buf).unwrap();

                    let response_packets = match &request_packet.value {
                        LdapValue::Primitive(_) => Err(LdapError::UnexpectedPacket),
                        LdapValue::Constructed(attributes) => {
                            match &attributes.get(1).unwrap().tag {
                                Tag::Application {
                                    operation,
                                    is_constructed: _,
                                } => match operation {
                                    LdapOperation::BindRequest => {
                                        Self::handle_bind_request(&request_packet)
                                    }
                                    LdapOperation::UnbindRequest => Ok(Vec::new()),
                                    LdapOperation::SearchRequest => {
                                        Self::handle_search_request(&request_packet)
                                    }
                                    _ => Err(LdapError::NotImplementedYet),
                                },
                                _ => Err(LdapError::UnexpectedPacket),
                            }
                        }
                    };

                    for packet in response_packets.unwrap() {
                        let response_bytes = packet.get_bytes();

                        socket
                            .write_all(&response_bytes)
                            .await
                            .expect("failed to write data to socket");
                    }
                }
            });
        }
    }

    pub fn handle_bind_request(
        request_packet: &LdapAttribute,
    ) -> Result<Vec<LdapAttribute>, LdapError> {
        let message_id_bytes = match &request_packet.value {
            LdapValue::Primitive(_) => todo!(),
            LdapValue::Constructed(attributes) => match attributes.first().unwrap().value.clone() {
                LdapValue::Primitive(value) => value,
                LdapValue::Constructed(_) => todo!(),
            },
        };

        let message_id = utils::bytes_to_i32(&message_id_bytes);

        let bind_response_attribute = LdapAttribute::new_result_attribute(
            LdapOperation::BindResponse,
            LdapResult::Success,
            "",
            "",
        );

        let bind_response_packet =
            LdapAttribute::new_packet(message_id, vec![bind_response_attribute]);

        Ok(vec![bind_response_packet])
    }

    pub fn handle_unbind_request(
        request_packet: &LdapAttribute,
    ) -> Result<Vec<LdapAttribute>, LdapError> {
        let message_id_bytes = match &request_packet.value {
            LdapValue::Primitive(_) => todo!(),
            LdapValue::Constructed(attributes) => match attributes.first().unwrap().value.clone() {
                LdapValue::Primitive(value) => value,
                LdapValue::Constructed(_) => todo!(),
            },
        };

        let message_id = utils::bytes_to_i32(&message_id_bytes);

        let bind_response_attribute = LdapAttribute::new_result_attribute(
            LdapOperation::BindResponse,
            LdapResult::Success,
            "",
            "",
        );

        let bind_response_packet =
            LdapAttribute::new_packet(message_id, vec![bind_response_attribute]);

        Ok(vec![bind_response_packet])
    }

    pub fn handle_search_request(
        request_packet: &LdapAttribute,
    ) -> Result<Vec<LdapAttribute>, LdapError> {
        let message_id_bytes = match &request_packet.value {
            LdapValue::Primitive(_) => todo!(),
            LdapValue::Constructed(attributes) => match attributes.first().unwrap().value.clone() {
                LdapValue::Primitive(value) => value,
                LdapValue::Constructed(_) => todo!(),
            },
        };

        let message_id = utils::bytes_to_i32(&message_id_bytes);

        let search_entry_packet = LdapAttribute::new_packet(
            message_id,
            vec![LdapAttribute::new(
                {
                    Tag::Application {
                        operation: LdapOperation::SearchResultEntry,
                        is_constructed: true,
                    }
                },
                LdapValue::Constructed(vec![
                    LdapAttribute::new(
                        Tag::Universal {
                            data_type: UniversalDataType::OctetString,
                            is_constructed: false,
                        },
                        LdapValue::Primitive(
                            "cn=testuser,cn=Users,dc=dev,dc=company,dc=com"
                                .as_bytes()
                                .to_vec(),
                        ),
                    ),
                    LdapAttribute::new(
                        Tag::Universal {
                            data_type: UniversalDataType::Sequence,
                            is_constructed: true,
                        },
                        LdapValue::Constructed(Vec::new()),
                    ),
                ]),
            )],
        );

        let search_done_packet = LdapAttribute::new_packet(
            message_id,
            vec![LdapAttribute::new_result_attribute(
                LdapOperation::SearchResultDone,
                LdapResult::Success,
                "",
                "",
            )],
        );

        Ok(vec![search_entry_packet, search_done_packet])
    }
}
