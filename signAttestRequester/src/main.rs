#![allow(non_snake_case)]
#![allow(unused_imports)]

use ed25519_compact::*;
use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
use std::net::{TcpListener, Shutdown};

#[derive(Debug, Default)]
struct Packet {
    msg : String,
    signature : Option<Signature>,
}

#[derive(Serialize, Deserialize)]
struct PacketOnWire {
    msg : String,
    signature_buf : Vec<u8>,
}


fn main() {
    println!("--Attestation Requester--");

    println!(">AR:KeyPair generation...");

    let key_pair = KeyPair::from_seed(Seed::generate());

    let dir_key : String = String::from("../keys/");
    let file_key_pub : String = dir_key.clone() + "key.pub";
    //et file_key_prv : String = dir_key.clone() + "key.prv";

    match fs::create_dir_all(dir_key.as_str()) {
        Ok(..)  => println!(">SR:PublicKey for signature verification is put in public trusted repository {:?} ", dir_key),
        Err(..) => panic!(">AR:Failed to create directory for KeyPair. Exit"),
    };

    let mut file_key_pub_fd = match File::create(file_key_pub.as_str()) {
        Ok(file) => file,
        Err(err) => panic!(">AR:Failed to create file for pub key with err {:?}", err), 
    };

    println!(">AR:PublicKey={:?}",key_pair.pk.to_pem().as_str().to_owned());
    file_key_pub_fd.write(key_pair.pk.to_pem().to_owned().as_bytes()).expect(">AR:Failed to write PublicKey in public file. Exit.");

    let listener = TcpListener::bind("localhost:5656").unwrap();
    println!("AS: Waiting for RemotePeer...");

    for stream in listener.incoming () {
        match stream {
            Err(err) => {
                panic!(">AR:Failed with error {:?}. Exit.", err);
            }
            Ok(mut stream) => {
                println!(">AR:Peer on {:?}", stream.peer_addr().unwrap());
                let mut old_sign : Option<Signature> = None;

                loop {
                    let mut reader = BufReader::new(&mut stream);
                    let received : Vec<u8> = reader.fill_buf().expect(">AR:Failed to read").to_vec(); 
                    let deserialized : PacketOnWire = deserialize(&received).unwrap(); 
                    reader.consume(received.len());

                    if deserialized.msg == "IDENTIFY".to_string() {
                        println!(">AR:Received request from RemotePeer to IDENTIFY...");
                        println!(">AR:Sending signed packet to RemotePeer...");
                        let signedPacket = Packet {
                            msg : "Frodo has the ring".to_string(),
                            signature : Some(key_pair.sk.sign("Frodo has the ring", Some(Noise::generate()))),
                        };
                        println!(">AR:Singed packet is msg=>{:?}; signature=>{:?}", signedPacket.msg, signedPacket.signature.unwrap().to_vec());
                        let packet_on_wire = PacketOnWire {
                                                msg : signedPacket.msg.to_owned(),
                                                signature_buf : signedPacket.signature.unwrap().to_owned().to_vec(),
                                            };
                        old_sign = Some(signedPacket.signature.unwrap().to_owned()); 
                        let serialized : Vec<u8> = serialize(&packet_on_wire).unwrap();
                        stream.write(&serialized).unwrap();
                    } else if deserialized.msg == "SIGNATURE-ACCEPTED".to_string() {
                        println!(">AR:Successful attestation=>Signature Accepted...");
                    } else if deserialized.msg == "IDENTIFY-AGAIN".to_string() {
                        println!(">AR:Rerequest from RemotePeer to IDENTIFY-AGAIN...");
                        let unsignedPacket = Packet {
                            msg : "Pippin has the ring".to_string(),
                                   signature : old_sign,
                            };
                        key_pair.pk.verify(unsignedPacket.msg.to_owned(), &unsignedPacket.signature.unwrap()).expect_err(">AR:Failed, unsigned packet asserted. Exit");
                        println!(">AR:Do not sign new packet=>Use previous accepted Signature...");
                        println!(">AR:New packet is msg=>{:?}; signature=>{:?}", unsignedPacket.msg, unsignedPacket.signature.unwrap().to_vec()) ;
                        let packet_on_wire = PacketOnWire {
                                                msg : unsignedPacket.msg.to_owned(),
                                                signature_buf : unsignedPacket.signature.unwrap().to_owned().to_vec(),
                                             };
                        let serialized : Vec<u8> = serialize(&packet_on_wire).unwrap(); 
                        stream.write(&serialized).unwrap();
                    } else if deserialized.msg.contains("EXIT"){
                        println!(">AR:Peer answered with=> {:?}.", deserialized.msg);
                        println!(">AR: Exit.");
                        return;
                    }
                }
            }    
        }
    }
}
