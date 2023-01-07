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
    tag::Tag,
    universal_data_type::UniversalDataType,
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

                let result_code_attribute = LdapAttribute::new(
                    Tag::Universal {
                        data_type: UniversalDataType::Enumerated,
                        is_constructed: false,
                    },
                    LdapValue::Primitive([LdapResult::Success as u8].to_vec()), // eeh..
                );

                let matched_dn_attribute = LdapAttribute::new(
                    Tag::Universal {
                        data_type: UniversalDataType::OctetString,
                        is_constructed: false,
                    },
                    LdapValue::Primitive(Vec::new()), // eeh..
                );

                let diagnostic_message_attribute = LdapAttribute::new(
                    Tag::Universal {
                        data_type: UniversalDataType::OctetString,
                        is_constructed: false,
                    },
                    LdapValue::Primitive(Vec::new()), // eeh..
                );

                let bind_response_attribute = LdapAttribute::new(
                    Tag::Application {
                        operation: LdapOperation::BindResponse,
                        is_constructed: true,
                    },
                    LdapValue::Constructed(vec![
                        result_code_attribute,
                        matched_dn_attribute,
                        diagnostic_message_attribute,
                    ]), // eeh..
                );

                let id = BigEndian::read_i32(&message_id);

                // should use the message id of the request
                let bind_response_packet =
                    LdapAttribute::new_packet(id, vec![bind_response_attribute]);

                /*

                public LdapResultAttribute(LdapOperation operation, LdapResult result, string matchedDN = "", string diagnosticMessage = "") : base(operation)
                       {
                           ChildAttributes.Add(new LdapAttribute(UniversalDataType.Enumerated, (byte)result));
                           ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, matchedDN));
                           ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, diagnosticMessage));
                           // todo add referral if needed
                           // todo bindresponse can contain more child attributes...
                       }



                                    var responsePacket = new LdapPacket(requestPacket.MessageId);
                               responsePacket.ChildAttributes.Add(new LdapResultAttribute(LdapOperation.BindResponse, response));
                               var responseBytes = responsePacket.GetBytes();
                               stream.Write(responseBytes, 0, responseBytes.Length);
                               return response == LdapResult.success; */

                let response_bytes = bind_response_packet.get_bytes();

                socket
                    .write_all(&response_bytes)
                    .await
                    .expect("failed to write data to socket");
                // }
            });
        }
    }
}
