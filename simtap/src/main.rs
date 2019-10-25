
mod types;
mod netif;
mod flowmap;
mod nat;
mod dnsresolv;


use crate::types::FiveTuple;
use crate::types::Connection;

use std::net::Ipv4Addr;
use dnsresolv::DNSCache;



#[cfg(target_os = "macos")]
	const UTUNHEADER: [u8; 4] = [0,0,0,2];
#[cfg(target_os = "linux")]
	const UTUNHEADER: [u8; 4] = [0,0,8,0];
	const UTUNHEADERLEN: usize = 4;


#[derive(Default)]
struct ConnectionManager {
    connections: flowmap::FlowMap,
    nat_map: nat::NatMap,
   	host_cache: DNSCache,
	wan_cache: DNSCache
}

fn process_l3(mut cm: &mut ConnectionManager, recv_buf: &[u8], len: usize, send_buf: &mut[u8]) -> usize { 
	let local_tun_addr:[ u8; 4] = [192,168,166,1];
	let local_tun_network = Ipv4Addr::new(192,168,166,0);
	let local_tun_network_size = 24; // /24 netmask

	let server_virt_addr : [u8; 4];
	let mut server_dst_addr: [u8; 4] =  [0; 4];

	let iph = etherparse::Ipv4HeaderSlice::from_slice(&recv_buf[UTUNHEADERLEN..len]).expect("could not parse rx ip header");
	let datai = UTUNHEADERLEN + iph.slice().len();

	// this is the tcp or above data
	let l3_payload = &recv_buf[datai..len];
	let l3_payload_bytes = len-datai;

	let mut ip: etherparse::Ipv4Header = iph.to_header();

	if ip.source == local_tun_addr {
		// originating from host 
		server_virt_addr = ip.destination;
		match cm.nat_map.get(server_virt_addr) { 
        	Some(d_ip) => {
                server_dst_addr = *d_ip;
        	},
        	None => { assert!(false, "failed to get nat mapping for {:?} ", server_virt_addr)},
		}

		ip.source = server_virt_addr;
		ip.destination = server_dst_addr;
		//println!("ip: found tun local flow: {:?} : {:?} ", ip.source, ip.destination);		
	} else { 
		// not originating from host
		// is it from virtual subnet (ala 192.168.166.0/24)
		let sig_octets = local_tun_network_size/8;
		let l_t_n_octets = local_tun_network.octets();
		let i_s_a_octets = iph.source_addr().octets();
		let d_s_a_octets = iph.destination_addr().octets();
		let local_network = &l_t_n_octets[0..sig_octets-1];
		let src_network = &i_s_a_octets[0..sig_octets-1];
		let _dst_network = &d_s_a_octets[0..sig_octets-1];

		if local_network == src_network {  
			// this packet is outbound from a virtual server 
			// no natting needed as this is handled on the os outbound inteface nat. 
			// so lets just have a hook for look and debug at moment. 
			println!("got packet from local virtual ip query: {:?}, hook and look only", ip);
			// All the ip headers corrently here. 
		} else { 
			// its not from the local virtual server set of ips so it must be inbound and needing 
			// our natting its destination from the virtual server to the host ip and the source from the 
			// external address to the virtual server address.
			let mut server_virt_addr: [u8; 4] = [0; 4];
			server_dst_addr = ip.destination;
			match cm.nat_map.get(server_dst_addr) { 
        		Some(sv_ip) => {
                	 server_virt_addr = *sv_ip;
        		},
        		None => { assert!(false, "failed to get nat mapping for {:?} ", server_dst_addr)},
			}
			//println!("ip: found inbound server flow: {:?} : {:?} ", ip.source, ip.destination);
			ip.source = server_dst_addr;
			ip.destination = local_tun_addr;
			//println!("ip: mapped inbound server flow: {:?} : {:?} ", ip.source, ip.destination);
		} 
	}

	// ip header manipulation now completed, 
	// lets process the next protocol layer up 
	// now prepare L3 packet to send, copying the utun, ip header and higher level protocol payload into send buffer. 
	//4 + ip + payload
	let pdu_len = UTUNHEADERLEN + ip.header_len() as usize + l3_payload_bytes;
	assert!(pdu_len <= 1504, "pdu too long: {}",pdu_len);

	send_buf[..UTUNHEADERLEN].clone_from_slice(&UTUNHEADER);
	// reform iph+payload with checksums 

	let mut unwritten = &mut send_buf[UTUNHEADERLEN..];
	ip.write(&mut unwritten).unwrap();
 	let tcp_len = process_tcp(&ip, &mut cm, &l3_payload, l3_payload_bytes, &mut unwritten);
 	assert!(UTUNHEADERLEN + ip.header_len() as usize + tcp_len <= 1504, "L3 pdu too long: {}",UTUNHEADERLEN + ip.header_len() as usize + tcp_len);

 	//return
 	UTUNHEADERLEN + ip.header_len() as usize + tcp_len
}


fn process_tcp(ip: &etherparse::Ipv4Header, cm: &mut ConnectionManager, recv_buf: &[u8], len: usize, send_buf: &mut[u8]) -> usize { 


	let tcph = etherparse::TcpHeaderSlice::from_slice(&recv_buf[..len]).expect("could not parse rx tcp header");
	let datai = tcph.slice().len();
	let tcp_payload = &recv_buf[datai..len];
	let tcp_payload_bytes = len-datai;

	let mut tcp = tcph.to_header();
	let nat_addr_entry:([u8; 4],[u8; 4]);
	let nat_port_entry: (u16, u16);


//	let query = FiveTuple {
//       src: (ip.source, tcph.source_port()),
//       dst: (ip.destination, tcph.destination_port()),
//       protocol: ip.protocol,
//    };
//
//	let r_query = FiveTuple {
//       src: (ip.destination, tcph.destination_port()),
//       dst: (ip.source, tcph.source_port()),
//       protocol: ip.protocol,
//    };
//
//	match cm.connections.get(query) { 
//		Some(con) => {
//			nat_addr_entry = con.nat_addr;
//            nat_port_entry = con.nat_port;
//            //println!("tcp: Found existing connection: {:?} : {:?} ", nat_addr_entry, nat_port_entry);
//		},
//		None => { 
//            let mut c = Connection { 
//				id: 1,
//				nat_addr: (ip.source,ip.destination),
//				nat_port: (tcph.source_port(),tcph.destination_port()),
//			};
//    		nat_addr_entry = c.nat_addr;
//	        nat_port_entry = c.nat_port;
//
//	        //println!("tcp: creating new connection: {:?} : {:?} ", nat_addr_entry, nat_port_entry);
//	        cm.connections.put(query,c);
//
//    		c = Connection { 
//				id: 1,
//				nat_addr: (ip.destination,ip.source),
//				nat_port: (tcph.destination_port(),tcph.source_port()),
//			};
//			cm.connections.put(r_query,c);
//		}
//	}

	let buffer_len = send_buf.len();

	// reform iph+tcph+payload with checksums refer to tcp.rs
	let mut unwritten = &mut send_buf[0..];
	tcp.write(&mut unwritten).unwrap();
    let tcp_header_ends_at = buffer_len - unwritten.len();

    if tcp_payload_bytes > 0 { 

		//eprintln!("unwritten: {}, payload bytes: {} ", unwritten.len(), &payload.len());

    	assert!(datai < len, "datai {} > len {}", datai, len);
    	assert!(unwritten.len() > (len-datai), " unwritten written too small: {} len: {}, datai: {}, ",unwritten.len(),len,datai );
    	//unwritten.copy_from_slice(&recv_buf[datai..len]);
    	unwritten[..tcp_payload_bytes].copy_from_slice(&tcp_payload);

	}

    // write send_buf the payload
    let payload_ends_at =  tcp_header_ends_at + tcp_payload_bytes;
   
    tcp.checksum = tcp.calc_checksum_ipv4(&ip, &send_buf[tcp_header_ends_at..payload_ends_at])
        .expect("failed to compute checksum");
	let mut tcp_header_buf = &mut send_buf[0..];
   	tcp.write(&mut tcp_header_buf).unwrap();

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
			//println!("-> : \tsrc: {} dst: {} len: {} proto: {} ",iph.source_addr(),iph.destination_addr(),len,iph.protocol());
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

		len = recv_buffer(&interface,&mut buf);

		// assuming this is ipv4 for the moment
		//let iph = etherparse::Ipv4HeaderSlice::from_slice(&buf[utun_header_len..len]).expect("could not parse rx ip header");
        
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[UTUNHEADERLEN..len]) {
    	    Ok(iph) => {	
		        //println!("<- : \tsrc: {} dst: {} len: {} proto: {} ",iph.source_addr(),iph.destination_addr(),len,iph.protocol());
		        match iph.protocol() { 
			        0x01 => {
			        	let outbuf_len = process_icmp(&mut cm, &buf, len, &mut out);
			        	send_buffer(&interface,&mut out,outbuf_len);	
			        },
			
			        0x06 => { 
			        	let outbuf_len = process_l3(&mut cm, &buf, len, &mut out);
			        	let iph = etherparse::Ipv4HeaderSlice::from_slice(& out[4..outbuf_len] as &[u8]).expect("could not parse tx ip header");
						//println!("L3-> : \tsrc: {} dst: {} len: {} proto: {} ",iph.source_addr(),iph.destination_addr(),outbuf_len,iph.protocol());
			       		//outbuf_len = process_tcp(&iph, &mut cm, &recv_buf, len, &mut send_buf);
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
