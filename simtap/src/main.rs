
mod types;
mod netif;
mod flowmap;
mod nat;
mod dnsresolv;

use crate::types::{FiveTuple, Connection};
use std::net::Ipv4Addr;
use dnsresolv::DNSCache;
use hermes::dns::protocol::{QueryType,ResultCode};


#[derive(Default)]
struct ConnectionManager {
    connections: flowmap::FlowMap,
    nat_map: nat::NatMap,
   	host_cache: DNSCache,
	wan_cache: DNSCache
}


fn process_tcp(cm: &mut ConnectionManager, recv_buf: &[u8], len: usize, send_buf: &mut[u8]) -> usize { 

	let _srv_dst = [172,217,0,36];
	let local_tun_addr = Ipv4Addr::new(192,168,166,1);
	let local_tun_network = Ipv4Addr::new(192,168,166,0);
	let local_tun_network_size = 24; // /24 netmask
	let server_virt_addr : Ipv4Addr;
	//let server_dst_addr = Ipv4Addr::new(172,217,0,36);
	let mut server_dst_addr =  Ipv4Addr::new(0,0,0,0);

	let utunheader:[u8; 4] = [0,0,0,2];
	let utun_header_len = utunheader.len();

	let iph = etherparse::Ipv4HeaderSlice::from_slice(&recv_buf[utun_header_len..len]).expect("could not parse rx ip header");
	let tcph = etherparse::TcpHeaderSlice::from_slice(&recv_buf[utun_header_len+iph.slice().len()..len]).expect("could not parse rx tcp header");
	let datai = utun_header_len + iph.slice().len() + tcph.slice().len();
	let payload = &recv_buf[datai..len];
	let payload_bytes = len-datai;


	let mut ip = iph.to_header();
	let mut tcp = tcph.to_header();

	let mut nat_addr_entry = (Ipv4Addr::new(127, 0, 0, 1),Ipv4Addr::new(127, 0, 0, 1));
	let mut nat_port_entry = (0,0);



	let query = FiveTuple {
       src: (iph.source_addr(), tcph.source_port()),
       dst: (iph.destination_addr(), tcph.destination_port()),
       protocol: iph.protocol(),
    };

	let _r_query = FiveTuple {
       src: (iph.destination_addr(), tcph.destination_port()),
       dst: (iph.source_addr(), tcph.source_port()),
       protocol: iph.protocol(),
    };

	// If src address is 192.168.166.1 (host ip address of tun)
	if iph.source_addr() == local_tun_addr {
		// This is the default outbound nat tranlation. 
		// 192.168.166.1: 5567 -> 192.168.166.2:443 -> 172.1.2.4:443
		// matching key ( ((192.168.166.1,5567), (192.168.166.2,443))
		// (o_src_addr:o_s_port -> o_dst_addr:o_d_port)
		//                nats to  
		//                        (o_dst_addr: o_s_port-> n_dst_addr: o_d_port) 

		// lookup map to find an existing connection
		match cm.connections.get(query) { 
			Some(con) => {
				nat_addr_entry = con.nat_addr;
	            nat_port_entry = con.nat_port;
	            //server_virt_addr = nat_addr_entry.0;
	            server_dst_addr = nat_addr_entry.1;
			},
			None => { 
				server_virt_addr = iph.destination_addr();

				match cm.nat_map.get(server_virt_addr) { 
                	Some(d_ip) => {
	                    server_dst_addr = *d_ip;
                	},
                	None => { assert!(false, "failed to get nat mapping for {} ", server_virt_addr.to_string());},
        		}

	            // did not find map entry, create one and set nat entries that need to be used. 
				// should we create the reverse map also?
				let c = Connection { 
							id: 1,
							nat_addr: (server_virt_addr,server_dst_addr),
							nat_port: (tcph.source_port(),tcph.destination_port()),
				};
				// setup values that were inserted into the map as they will be used for this packet. 
				nat_addr_entry = c.nat_addr;
	            nat_port_entry = c.nat_port;
	            cm.connections.put(query,c);

	            let r_query = FiveTuple {
       				src: (server_dst_addr, tcph.destination_port()),
       				dst: (server_virt_addr, tcph.source_port()),
       				protocol: iph.protocol(),
    			};
    			let c = Connection { 
							id: 1,
							nat_addr: (iph.destination_addr(),iph.source_addr()),
							nat_port: (tcph.destination_port(),tcph.source_port()),
						};

				cm.connections.put(r_query,c);

			},
		}

	    //ip.source = nat_addr_entry.0.octets();
		ip.source = ip.destination;
		tcp.source_port = nat_port_entry.0;
		// no change to ip.source_port
		ip.destination = nat_addr_entry.1.octets();
		ip.destination = server_dst_addr.octets();
		tcp.destination_port = nat_port_entry.1;
		// no change to ip.destination_port

	} else { 
		let sig_octets = local_tun_network_size/8;
		//let mut local_network = [0u8,4]; 
		//let mut src_network =  [0u8,4]; 
		//let mut dst_network = [0u8,4]; 
		let l_t_n_octets = local_tun_network.octets();
		let i_s_a_octets = iph.source_addr().octets();
		let d_s_a_octets = iph.destination_addr().octets();

		//for i in 0..sig_octets-1 { 
		//	local_network[i] = l_t_n_octets[i];
		//	src_network[i] = i_s_a_octets[i];
		//	dst_network[i] = d_s_a_octets[i];
		//}

		let local_network = &l_t_n_octets[0..sig_octets-1];
		let src_network = &i_s_a_octets[0..sig_octets-1];
		let _dst_network = &d_s_a_octets[0..sig_octets-1];



		// if src address is in ip range that is target of tun but not the host address then its inbound
		if local_network == src_network { 
			// this packet is outbound from a virtual server 
			// no natting needed as this is handled on the os outbound inteface nat. 
			// so lets just have a hook for look and debug at moment. 
			eprintln!("got packet from local virtual ip query: {:?}, hook and look only", query);

			// All the ip headers and tcp port numbers should be oriented corrently here. 


		} else { 
			// its not from the local virtual server set of ips so it must be inbound and needing NAT
			// to get it going to the right place (assuming that there is no inbound connections!!) 

			// lookup map to find an existing connection, this will be one of the reverse query entries that was added earlier

		match cm.connections.get(query) { 
			Some(con) => {
				nat_addr_entry = con.nat_addr;
	            nat_port_entry = con.nat_port;
			},
			None => { 
	            eprintln!("got packet for unknown connection, should not happen in this case {:?}", query);
			},
		}

		// This is the inboound nat translation, 
		// 172.1.2.4:443 ->  192.168.166.2:5667 -> 192.168.166.1: 5567
		// matching key ( ((172.1.2.4,443), (192.168.166.2,5567))
		// (o_src_addr:o_s_port -> o_dst_addr:o_d_port)
		// 	               nats to  
		//                        (o_dst_addr: o_s_port-> n_dst_addr: o_d_port) 
		
		ip.source = nat_addr_entry.0.octets();
		tcp.source_port = nat_port_entry.0;
		// no change to ip.source_port
		ip.destination = nat_addr_entry.1.octets();
		tcp.destination_port = nat_port_entry.1;
		// no change to ip.destination_port

		}
	}


	
	//4 + ip +  tcp +  tcp payload
	let pdu_len = utun_header_len + ip.header_len() as usize + tcp.header_len() as usize + payload_bytes;
	assert!(pdu_len <= 1504, "pdu too long: {}",pdu_len);
	let buffer_len = send_buf.len();

	// place proper tun header on the out -- utun_header_len(4)
	send_buf[..utun_header_len].clone_from_slice(&utunheader);

	// reform iph+tcph+payload with checksums refer to tcp.rs
	let mut unwritten = &mut send_buf[utun_header_len..];
	ip.write(&mut unwritten).unwrap();
	let ip_header_ends_at = buffer_len - unwritten.len();

	tcp.write(&mut unwritten).unwrap();
    let tcp_header_ends_at = buffer_len - unwritten.len();


    if payload_bytes > 0 { 

		//eprintln!("unwritten: {}, payload bytes: {} ", unwritten.len(), &payload.len());

    	assert!(datai < len, "datai {} > len {}", datai, len);
    	assert!(unwritten.len() > (len-datai), " unwritten written too small: {} len: {}, datai: {}, ",unwritten.len(),len,datai );
    	//unwritten.copy_from_slice(&recv_buf[datai..len]);
    	unwritten[..payload_bytes].copy_from_slice(&payload);

	}

    // write send_buf the payload
    let payload_ends_at =  tcp_header_ends_at + payload_bytes;
   
    tcp.checksum = tcp.calc_checksum_ipv4(&ip, &send_buf[tcp_header_ends_at..payload_ends_at])
        .expect("failed to compute checksum");
	let mut tcp_header_buf = &mut send_buf[ip_header_ends_at..tcp_header_ends_at];
   	tcp.write(&mut tcp_header_buf).unwrap();

    // buffer should now have complete packet
    //&out[..payload_ends_at]
	//println!("send_buf: {} bytes", payload_ends_at);
	//println!("{:?}", &send_buf[..payload_ends_at]);
	payload_ends_at
}

fn process_udp(_cm: &mut ConnectionManager, recv_buf: &[u8], _len: usize, _send_buf: &mut[u8]) -> usize { 
	println!("dropping udp: {:?} bytes", &recv_buf[..64]);
	0
}

fn process_icmp(_cm: &mut ConnectionManager, recv_buf: &[u8], _len: usize, _send_buf: &mut[u8]) -> usize { 
	println!("dropping icmp: {:?} bytes", &recv_buf[..64]);
	0
}

fn recv_buffer(interface: &netif::Interface, mut recv_buf: &mut[u8]) -> usize { 
	let mut len: usize = 0;
	match interface.recv(&mut recv_buf) {
				Ok(n) => { len = n;
							//println!("received on {:?}: {} bytes", fd, n);
							//println!("{:?}", &recv_buf[..64]);
						  },
				Err(e) => eprintln!("recv function failed on {}: {:?}", interface.name(), e),
			}
	len
}

fn send_buffer(interface: &netif::Interface, send_buf: &[u8], len: usize) { 
	match interface.send(&send_buf[..len]) { 
		Ok(_n_sent) => { 
			//println!("wrote {} bytes", _n_sent) 
			let iph = etherparse::Ipv4HeaderSlice::from_slice(&send_buf[4..len]).expect("could not parse tx ip header");
			println!("-> : \tsrc: {} dst: {} len: {} proto: {} ",iph.source_addr(),iph.destination_addr(),len,iph.protocol());
		},
		Err(e) => println!("send function failed on {}: {:?}", interface.name(),e),
		}
}


fn main() {

	let mut cm = ConnectionManager::default();

	//use hermes::dns::protocol::{DnsRecord, QueryType, ResultCode, TransientTtl};
	// host_dns cache holds the ip of locally natted app targets


	dnsresolv::initialize_caches(&mut cm.host_cache, &mut cm.wan_cache,&mut cm.nat_map);

	//if let Some(packet) = cm.host_cache.lookup("google.com", QueryType::A) { 
	//	assert_eq!(ResultCode::NOERROR, packet.header.rescode);
	//}

	//if let Some(packet) = cm.wan_cache.lookup("google.com", QueryType::A) { 
	//	assert_eq!(ResultCode::NOERROR, packet.header.rescode);
	//}

	//let ip_a =  Ipv4Addr::new(192,168,166,3);
    //match cm.nat_map.get(ip_a) { 
    //    Some(ip) => {
    //        println!("nat_map - A: {}, ip_b: {} ", ip_a.to_string(), ip.to_string());
    //    },
    //    None => { println!( "failed to get nat mapping ip_a->ip_b for {} ", ip_a.to_string());},
	//} 


	//let srv_dst = [10,33,116,118];
	let _name = "utun1";
	#[cfg(target_os = "macos")]
	let interface = netif::Interface::new(mac_utun::get_utun().expect("Error, did not get a untun returned")); 
	#[cfg(target_os = "linux")]
	let interface = netif::Interface::new(tun_tap::Iface::new(_name, tun_tap::Mode::Tun).unwrap());
	//let interface = netif::Interface::new(tun_tap::Iface::without_packet_info(_name, tun_tap::Mode::Tun).unwrap());

 	

	loop {
	
	    let mut buf = [0u8; 2004];
	    let mut out = [0u8; 2004];
	    let len: usize;
	    let utunheader:[u8; 4] = [0,0,8,0];
		let utun_header_len = utunheader.len();

		len = recv_buffer(&interface,&mut buf);

		// assuming this is ipv4 for the moment
		//let iph = etherparse::Ipv4HeaderSlice::from_slice(&buf[utun_header_len..len]).expect("could not parse rx ip header");
        
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[utun_header_len..len]) {
    	    Ok(iph) => {	
		        println!("<- : \tsrc: {} dst: {} len: {} proto: {} ",iph.source_addr(),iph.destination_addr(),len,iph.protocol());
		        match iph.protocol() { 
			        0x01 => {
			        	let outbuf_len = process_icmp(&mut cm, &buf, len, &mut out);
			        	send_buffer(&interface,&mut out,outbuf_len);	
			        },
			
			        0x06 => { 
			        	let outbuf_len = process_tcp(&mut cm, &buf, len, &mut out);
			        	send_buffer(&interface,&mut out,outbuf_len);	
			        },

			        17 => { 
			        	let outbuf_len = process_udp(&mut cm, &buf, len, &mut out);
			        	send_buffer(&interface,&mut out,outbuf_len);
			        },
        
        			41 => println!("ipv6"),
        			_ => println!("unknown: {} ", iph.protocol()),
        	        }
            }
            Err(e) => {
                eprintln!("ignoring non ipv4  packet {:?}", e);
            }
      	}
    }		
}
