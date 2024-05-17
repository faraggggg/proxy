use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc, Mutex};

use std::thread::{spawn, JoinHandle};


type Job = Box<dyn Send + FnOnce() + 'static>;

pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: Option<Sender<Job>>,
}

impl ThreadPool {
    /// Create a new ThreadPool
    ///
    /// size is the number of threads inside the pool
    ///
    /// # Panics
    ///
    /// panics if the size is 0
    pub fn new(size: usize) -> Self {
        assert!(size > 0);

        let mut workers: Vec<Worker> = Vec::with_capacity(size);

        let (sender, receiver) = mpsc::channel::<Job>();
        let receiver = Arc::new(Mutex::new(receiver));

        for i in 0..size {
            let worker = Worker::new(i, Arc::clone(&receiver));
            workers.push(worker);
        }

        ThreadPool {
            workers,
            sender: Some(sender),
        }
    }

    /// Use the thread pool to execute a task
    ///
    /// the task must implement FnOnce(), Send and has a static lifetime
    ///
    pub fn execute<F>(&self, f: F)
        where
            F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);
        self.sender.as_ref().unwrap().send(job).unwrap()
    }
}

impl Drop for ThreadPool {
    /// close the channel, join the threads and leaving a none in the worker's optional thread.
    fn drop(&mut self) {
        drop(self.sender.take());

        for worker in &mut self.workers {
            println!("Shutting down worker {}", worker.id);

            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}

/// Workers that have an optional thread and an id
///
/// the option is used when handling the shutdown, thus, used in the drop implementation.
struct Worker {
    id: usize,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    /// create a new worker that loops and waits for a job to be sent to the channel.
    ///
    /// Does not do a spinning loop, instead sleeps until a job is available.
    ///
    /// Shuts down when the sender is closed, due to the mpsc channel implementation.
    ///
    /// # Panics
    ///
    /// panics if the lock is in a poisonous state.
    ///
    /// in a production setting, we might want to handle that state.
    ///
    fn new(id: usize, receiver: Arc<Mutex<Receiver<Job>>>) -> Self {
        let thread = spawn(move || loop {
            let message = receiver.lock().unwrap().recv();
            match message {
                Ok(job) => {
                    println!("Thread {} got a job and is executing it!", id);
                    job();
                }
                Err(e) => {
                    eprintln!(
                        "Worker {} disconnected; shutting down. closing due to: {}",
                        id, e
                    );
                    break;
                }
            }
        });

        Worker {
            id,
            thread: Some(thread),
        }
    }
}

mod proxy {
    use pnet::datalink::{self, NetworkInterface};

    use pnet::packet::arp::ArpPacket;
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
    use pnet::packet::icmpv6::Icmpv6Packet;
    use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::ipv6::Ipv6Packet;
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::udp::UdpPacket;
    use pnet::packet::Packet;
    use pnet::util::MacAddr;

    use std::env;
    use std::io::{self, Write};
    use std::net::IpAddr;
    use std::process;

    fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
        let udp = UdpPacket::new(packet);

        if let Some(udp) = udp {
            println!(
                "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
                interface_name,
                source,
                udp.get_source(),
                destination,
                udp.get_destination(),
                udp.get_length()
            );
        } else {
            println!("[{}]: Malformed UDP Packet", interface_name);
        }
    }

    fn handle_icmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
        let icmp_packet = IcmpPacket::new(packet);
        if let Some(icmp_packet) = icmp_packet {
            match icmp_packet.get_icmp_type() {
                IcmpTypes::EchoReply => {
                    let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                    println!(
                        "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                        interface_name,
                        source,
                        destination,
                        echo_reply_packet.get_sequence_number(),
                        echo_reply_packet.get_identifier()
                    );
                }
                IcmpTypes::EchoRequest => {
                    let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                    println!(
                        "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                        interface_name,
                        source,
                        destination,
                        echo_request_packet.get_sequence_number(),
                        echo_request_packet.get_identifier()
                    );
                }
                _ => println!(
                    "[{}]: ICMP packet {} -> {} (type={:?})",
                    interface_name,
                    source,
                    destination,
                    icmp_packet.get_icmp_type()
                ),
            }
        } else {
            println!("[{}]: Malformed ICMP Packet", interface_name);
        }
    }

    fn handle_icmpv6_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
        let icmpv6_packet = Icmpv6Packet::new(packet);
        if let Some(icmpv6_packet) = icmpv6_packet {
            println!(
                "[{}]: ICMPv6 packet {} -> {} (type={:?})",
                interface_name,
                source,
                destination,
                icmpv6_packet.get_icmpv6_type()
            )
        } else {
            println!("[{}]: Malformed ICMPv6 Packet", interface_name);
        }
    }

    fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
        let tcp = TcpPacket::new(packet);
        if let Some(tcp) = tcp {
            println!(
                "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
                interface_name,
                source,
                tcp.get_source(),
                destination,
                tcp.get_destination(),
                packet.len()
            );
        } else {
            println!("[{}]: Malformed TCP Packet", interface_name);
        }
    }

    fn handle_transport_protocol(
        interface_name: &str,
        source: IpAddr,
        destination: IpAddr,
        protocol: IpNextHeaderProtocol,
        packet: &[u8],
    ) {
        match protocol {
            IpNextHeaderProtocols::Udp => {
                handle_udp_packet(interface_name, source, destination, packet)
            }
            IpNextHeaderProtocols::Tcp => {
                handle_tcp_packet(interface_name, source, destination, packet)
            }
            IpNextHeaderProtocols::Icmp => {
                handle_icmp_packet(interface_name, source, destination, packet)
            }
            IpNextHeaderProtocols::Icmpv6 => {
                handle_icmpv6_packet(interface_name, source, destination, packet)
            }
            _ => println!(
                "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                interface_name,
                match source {
                    IpAddr::V4(..) => "IPv4",
                    _ => "IPv6",
                },
                source,
                destination,
                protocol,
                packet.len()
            ),
        }
    }

    fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) {
        let header = Ipv4Packet::new(ethernet.payload());
        if let Some(header) = header {
            handle_transport_protocol(
                interface_name,
                IpAddr::V4(header.get_source()),
                IpAddr::V4(header.get_destination()),
                header.get_next_level_protocol(),
                header.payload(),
            );
        } else {
            println!("[{}]: Malformed IPv4 Packet", interface_name);
        }
    }

    fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket) {
        let header = Ipv6Packet::new(ethernet.payload());
        if let Some(header) = header {
            handle_transport_protocol(
                interface_name,
                IpAddr::V6(header.get_source()),
                IpAddr::V6(header.get_destination()),
                header.get_next_header(),
                header.payload(),
            );
        } else {
            println!("[{}]: Malformed IPv6 Packet", interface_name);
        }
    }

    fn handle_arp_packet(interface_name: &str, ethernet: &EthernetPacket) {
        let header = ArpPacket::new(ethernet.payload());
        if let Some(header) = header {
            println!(
                "[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
                interface_name,
                ethernet.get_source(),
                header.get_sender_proto_addr(),
                ethernet.get_destination(),
                header.get_target_proto_addr(),
                header.get_operation()
            );
        } else {
            println!("[{}]: Malformed ARP Packet", interface_name);
        }
    }

    pub fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket) {
        let interface_name = &interface.name[..];
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet),
            EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet),
            EtherTypes::Arp => handle_arp_packet(interface_name, ethernet),
            _ => println!(
                "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
                interface_name,
                ethernet.get_source(),
                ethernet.get_destination(),
                ethernet.get_ethertype(),
                ethernet.packet().len()
            ),
        }
    }
}
pub use proxy::handle_ethernet_frame;