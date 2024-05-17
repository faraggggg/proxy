extern crate pnet;

use std::{env, io, process};
use pnet::datalink;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use proxy::ThreadPool;
use proxy::handle_ethernet_frame;
use std::io::Write;


fn main() {
    use pnet::datalink::Channel::Ethernet;
    let pool : ThreadPool = ThreadPool::new(5);
    let iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            writeln!(std::io::stderr(), "USAGE: proxy <NETWORK INTERFACE>").unwrap();
            process::exit(1);
        }
    };
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("proxy: unhandled channel type"),
        Err(e) => panic!("proxy: unable to create channel: {}", e),
    };

    loop {
        let mut buf: [u8; 1600] = [0u8; 1600];
        let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        match rx.next() {
            Ok(packet) => {
                let f = handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap());
                pool.execute(move || f)
            }
            Err(e) => panic!("proxy: unable to receive packet: {}", e),
        }
    }
}