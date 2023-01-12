use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    vec,
};

use tokio::{io::AsyncWriteExt, net::TcpListener};

use crate::{
    ldap_attribute::{LdapAttribute, LdapValue},
    ldap_error::LdapError,
    ldap_operation::LdapOperation,
    ldap_result::LdapResult,
    tag::Tag,
    universal_data_type::UniversalDataType,
    utils::{self, dump_packet},
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
            let (mut socket, peer_address) = listener.accept().await?;
            println!("Got client from {:?}", peer_address);

            tokio::spawn(async move {
                let mut is_client_bound = false;

                while let Some(request_packet) =
                    LdapAttribute::parse_packet_from_stream(&mut socket)
                        .await
                        .unwrap()
                {
                    dump_packet(&request_packet);

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
                                        // if (is_client_bound) {
                                        Self::handle_search_request(&request_packet)
                                        // } else {
                                        //     Err(LdapError)
                                        // }
                                    }
                                    _ => Err(LdapError::NotImplementedYet),
                                },
                                _ => Err(LdapError::UnexpectedPacket),
                            }
                        }
                    };

                    match response_packets {
                        Ok(response_packets) => {
                            for packet in response_packets {
                                let response_bytes = packet.get_bytes();

                                socket
                                    .write_all(&response_bytes)
                                    .await
                                    .expect("failed to write data to socket");
                            }
                        }
                        Err(e) => println!(
                            "Something went haywire getting response packet from handler?! {}",
                            e
                        ),
                    }
                }

                println!("socket to {:?} closed by peer", peer_address);
            });
        }
    }

    pub fn handle_bind_request(
        request_packet: &LdapAttribute,
    ) -> Result<Vec<LdapAttribute>, LdapError> {
        let credendials = if let LdapValue::Constructed(attributes) = &request_packet.value {
            if let LdapValue::Constructed(bind_attributes) = &attributes[1].value {
                if let (
                    LdapValue::Primitive(username_bytes),
                    LdapValue::Primitive(password_bytes),
                ) = (&bind_attributes[1].value, &bind_attributes[2].value)
                {
                    Some((
                        String::from_utf8(username_bytes.clone()).unwrap(),
                        String::from_utf8(password_bytes.clone()).unwrap(),
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let result = match credendials {
            Some((username, password)) => {
                if username == "fooo" && password == "ooof" {
                    LdapResult::Success
                } else {
                    LdapResult::InvalidCredentials
                }
            }
            None => LdapResult::InvalidCredentials,
        };

        let bind_response_packet = LdapAttribute::new_packet(
            Self::get_message_id(request_packet)?,
            vec![LdapAttribute::new_result_attribute(
                LdapOperation::BindResponse,
                result,
                "",
                "",
            )],
        );

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

    /*
    /// <summary>
        /// Handle search requests
        /// </summary>
        /// <param name="searchRequest"></param>
        /// <returns></returns>
        private void HandleSearchRequest(NetworkStream stream, LdapPacket requestPacket)
        {
            var searchRequest = requestPacket.ChildAttributes.SingleOrDefault(o => o.LdapOperation == LdapOperation.SearchRequest);
            var filter = searchRequest.ChildAttributes[6];

            if ((LdapFilterChoice)filter.ContextType == LdapFilterChoice.equalityMatch && filter.ChildAttributes[0].GetValue<String>() == "sAMAccountName" && filter.ChildAttributes[1].GetValue<String>() == "testuser") // equalityMatch
            {
                var responseEntryPacket = new LdapPacket(requestPacket.MessageId);
                var searchResultEntry = new LdapAttribute(LdapOperation.SearchResultEntry);
                searchResultEntry.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, "cn=testuser,cn=Users,dc=dev,dc=company,dc=com"));
                searchResultEntry.ChildAttributes.Add(new LdapAttribute(UniversalDataType.Sequence));
                responseEntryPacket.ChildAttributes.Add(searchResultEntry);
                var responsEntryBytes = responseEntryPacket.GetBytes();
                stream.Write(responsEntryBytes, 0, responsEntryBytes.Length);
            }

            var responseDonePacket = new LdapPacket(requestPacket.MessageId);
            responseDonePacket.ChildAttributes.Add(new LdapResultAttribute(LdapOperation.SearchResultDone, LdapResult.success));
            var responseDoneBytes = responseDonePacket.GetBytes();
            stream.Write(responseDoneBytes, 0, responseDoneBytes.Length);
        } */
    pub fn handle_search_request(
        request_packet: &LdapAttribute,
    ) -> Result<Vec<LdapAttribute>, LdapError> {
        let message_id = Self::get_message_id(request_packet)?;

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

    fn get_message_id(packet: &LdapAttribute) -> Result<i32, LdapError> {
        Ok(utils::bytes_to_i32(
            match &packet.value {
                LdapValue::Primitive(_) => None,
                LdapValue::Constructed(attributes) => {
                    attributes.first().and_then(|v| match &v.value {
                        LdapValue::Primitive(value) => Some(value),
                        LdapValue::Constructed(_) => None,
                    })
                }
            }
            .ok_or(LdapError::MalformedPacket(
                "No message id could be parsed".to_string(),
            ))?,
        ))
    }
}
