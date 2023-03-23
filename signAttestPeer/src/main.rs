#![allow(non_snake_case)]
#![allow(unused_imports)]

use ed25519_compact::*;
use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};
use std::fs;
use std::time::Duration;
use std::io::BufReader;
use std::io::prelude::*;
use std::net::{TcpStream, SocketAddr, ToSocketAddrs};

#[derive(Serialize, Deserialize)]
struct PacketOnWire {
    msg : String,
    signature_buf : Vec<u8>,
}

fn main() {
    println!("##RemotePeer##");

    let pub_key_pem = fs::read_to_string("../keys/key.pub").unwrap();
    let pub_key : PublicKey = PublicKey::from_pem(pub_key_pem.to_owned().as_str()).unwrap();

    match TcpStream::connect(&"localhost:5656") {
        Err(err) => {
            panic!("#RP:Failed to connect... Exit with error {:?}.", err);
        }
        Ok(mut stream) => {
            println!("#RP:Connected...");
            let mut identifyed : bool = false;
            
            loop {
                let request : Option<Vec<u8>>;
                if !identifyed {
                    request = Some(create_request("IDENTIFY".to_string()));
                } else {
                    request = Some(create_request("IDENTIFY-AGAIN".to_string()));
                }
                
                stream.write(&request.unwrap().to_owned()).unwrap();

                let mut reader = BufReader::new(&mut stream);
                let received : Vec<u8> = reader.fill_buf().expect("#RP:Failed to read stream.").to_vec();
                let deserialized : PacketOnWire = deserialize(&received).unwrap();
                reader.consume(received.len());

                println!("#PR:Received msg=>{:?} with singature=>{:?}", deserialized.msg, deserialized.signature_buf);

                if !signature_check(&deserialized, &pub_key) {
                    let _exit =  "EXIT-BAD-SIGNATURE for msg:==>".to_string() + deserialized.msg.as_str();// .msg.as_str();
                    stream.write(&(create_request(_exit))).unwrap();
                    return;
                } else if !identifyed {
                    identifyed = true;
                    stream.write(&create_request("SIGNATURE-ACCEPTED".to_string())).unwrap();
                }
            }
        }
    }   
}

fn create_request (request : String) -> Vec<u8> {
            let packet_on_wire = PacketOnWire {
                msg : request,
                signature_buf : Vec::new(),
            };
            let serialized = serialize(&packet_on_wire).unwrap(); 
            println!("#PR:Send==>{:?}", packet_on_wire.msg);
            serialized
}

fn signature_check (packet : &PacketOnWire, pub_key : &PublicKey) -> bool {
    let signature : Signature = Signature::new(packet.signature_buf.to_owned().as_slice().try_into().unwrap());
    println!("#RP:Verifying identity of sender by the signature of sended packet with PublicKey found in '../keys/key.pub'");
    match pub_key.verify(packet.msg.to_owned(), &signature) {
        Err(_err) => {
            println!("#PR:Received message was NOT SIGNED by KNOWN peer.");
            return false;
        },
        Ok(_) => {
            println!("#PR:Message was SIGNED by KNOWN peer.");
            return true;
        }
    }
}
