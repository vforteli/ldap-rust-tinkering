use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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

                loop {
                    let n = socket
                        .read(&mut buf)
                        .await
                        .expect("failed to read data from socket");

                    if n == 0 {
                        return;
                    }

                    let request_packet = LdapAttribute::parse(&buf).unwrap();

                    let response_packet = match &request_packet.value {
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
                                    LdapOperation::UnbindRequest => Ok(None),
                                    LdapOperation::SearchRequest => {
                                        Self::handle_search_request(&request_packet)
                                    }
                                    _ => Err(LdapError::NotImplementedYet),
                                },
                                _ => Err(LdapError::UnexpectedPacket),
                            }
                        }
                    };

                    match response_packet.unwrap() {
                        Some(packet) => {
                            let response_bytes = packet.get_bytes();

                            println!("response bytes: {:?}", response_bytes);

                            socket
                                .write_all(&response_bytes)
                                .await
                                .expect("failed to write data to socket");

                            socket.flush().await.expect("hu?");
                        }
                        None => (),
                    }
                }
            });
        }
    }

    pub fn handle_bind_request(
        request_packet: &LdapAttribute,
    ) -> Result<Option<LdapAttribute>, LdapError> {
        let message_id_bytes = match &request_packet.value {
            LdapValue::Primitive(_) => todo!(),
            LdapValue::Constructed(attributes) => match attributes.first().unwrap().value.clone() {
                LdapValue::Primitive(value) => value,
                LdapValue::Constructed(_) => todo!(),
            },
        };

        let message_id = utils::bytes_to_i32(&message_id_bytes);

        let bind_response_attribute =
            LdapAttribute::new_result_attribute(LdapOperation::BindResponse, LdapResult::Success);

        let bind_response_packet =
            LdapAttribute::new_packet(message_id, vec![bind_response_attribute]);

        Ok(Some(bind_response_packet))
    }

    pub fn handle_unbind_request(
        request_packet: &LdapAttribute,
    ) -> Result<Option<LdapAttribute>, LdapError> {
        let message_id_bytes = match &request_packet.value {
            LdapValue::Primitive(_) => todo!(),
            LdapValue::Constructed(attributes) => match attributes.first().unwrap().value.clone() {
                LdapValue::Primitive(value) => value,
                LdapValue::Constructed(_) => todo!(),
            },
        };

        let message_id = utils::bytes_to_i32(&message_id_bytes);

        let bind_response_attribute =
            LdapAttribute::new_result_attribute(LdapOperation::BindResponse, LdapResult::Success);

        let bind_response_packet =
            LdapAttribute::new_packet(message_id, vec![bind_response_attribute]);

        Ok(Some(bind_response_packet))
    }

    pub fn handle_search_request(
        request_packet: &LdapAttribute,
    ) -> Result<Option<LdapAttribute>, LdapError> {
        let message_id_bytes = match &request_packet.value {
            LdapValue::Primitive(_) => todo!(),
            LdapValue::Constructed(attributes) => match attributes.first().unwrap().value.clone() {
                LdapValue::Primitive(value) => value,
                LdapValue::Constructed(_) => todo!(),
            },
        };

        let message_id = utils::bytes_to_i32(&message_id_bytes);

        let search_done_attribute = LdapAttribute::new_result_attribute(
            LdapOperation::SearchResultDone,
            LdapResult::Success,
        );

        let search_done_packet = LdapAttribute::new_packet(message_id, vec![search_done_attribute]);

        Ok(Some(search_done_packet))

        /*
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
           stream.Write(responseDoneBytes, 0, responseDoneBytes.Length); */
    }
}
