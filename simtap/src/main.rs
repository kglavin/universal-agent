
mod types;
mod netif;
mod flowmap;
mod nat;
mod dnsresolv;


use crate::types::FiveTuple;
use crate::types::Connection;

use std::net::Ipv4Addr;
use dnsresolv::DNSCache;

use hermes::dns::buffer::{BytePacketBuffer};
use hermes::dns::protocol::{DnsRecord,QueryType,TransientTtl};




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
		//println!("ip: found tun local flow: {:?} : {:?}  carrying {} bytes", ip.source, ip.destination, l3_payload_bytes);		
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

	let iphl = ip.ihl()as usize *4;
	let mut unwritten = &mut send_buf[UTUNHEADERLEN+iphl..];
	// cannot write ip header until we know the payload lenght that may change do to higher level payload changes
	//ip.write(&mut unwritten).unwrap();

	let mut l3_len_out: usize = 0;

    match ip.protocol { 
        0x01 => {
			l3_len_out = process_icmp(&ip, &mut cm, &l3_payload, l3_payload_bytes, &mut unwritten);	
        },

        0x06 => { 
			l3_len_out = process_tcp(&ip, &mut cm, &l3_payload, l3_payload_bytes, &mut unwritten);	
        },

        17 => { 
        	l3_len_out = process_udp(&ip, &mut cm, &l3_payload, l3_payload_bytes, &mut unwritten);	
        },
		_ => println!("unknown: {} ", ip.protocol),
    }
	
	let mut unwritten = &mut send_buf[UTUNHEADERLEN..UTUNHEADERLEN+iphl];
	ip.payload_len = l3_len_out as u16;
	ip.write(&mut unwritten).unwrap();
 	assert!(UTUNHEADERLEN + ip.header_len() as usize + l3_len_out <= 1504, "L3 pdu too long: {}",UTUNHEADERLEN + ip.header_len() as usize + l3_len_out);
 	//return
 	UTUNHEADERLEN + ip.header_len() as usize + l3_len_out
}


fn process_tcp(ip: &etherparse::Ipv4Header, cm: &mut ConnectionManager, recv_buf: &[u8], len: usize, send_buf: &mut[u8]) -> usize { 


	let tcph = etherparse::TcpHeaderSlice::from_slice(&recv_buf[..len]).expect("could not parse rx tcp header");
	let datai = tcph.slice().len();
	let tcp_payload = &recv_buf[datai..len];
	let tcp_payload_bytes = len-datai;

	let mut tcp = tcph.to_header();
	let nat_addr_entry:([u8; 4],[u8; 4]);
	let nat_port_entry: (u16, u16);


	let query = FiveTuple {
       src: (ip.source, tcph.source_port()),
       dst: (ip.destination, tcph.destination_port()),
       protocol: ip.protocol,
    };

	let r_query = FiveTuple {
       src: (ip.destination, tcph.destination_port()),
       dst: (ip.source, tcph.source_port()),
       protocol: ip.protocol,
    };

	match cm.connections.get(query) { 
		Some(con) => {
			nat_addr_entry = con.nat_addr;
            nat_port_entry = con.nat_port;
            //println!("tcp: Found existing connection: {:?} : {:?} ", nat_addr_entry, nat_port_entry);
		},
		None => { 
            let mut c = Connection { 
				id: 1,
				nat_addr: (ip.source,ip.destination),
				nat_port: (tcph.source_port(),tcph.destination_port()),
			};
    		nat_addr_entry = c.nat_addr;
	        nat_port_entry = c.nat_port;

	        //println!("tcp: creating new connection: {:?} : {:?} ", nat_addr_entry, nat_port_entry);
	        cm.connections.put(query,c);

    		c = Connection { 
				id: 1,
				nat_addr: (ip.destination,ip.source),
				nat_port: (tcph.destination_port(),tcph.source_port()),
			};
			cm.connections.put(r_query,c);
		}
	}

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

fn process_udp(ip: &etherparse::Ipv4Header, cm: &mut ConnectionManager, recv_buf: &[u8], len: usize, send_buf: &mut[u8]) -> usize { 
	// doing no processing at moment, just copy udp payload from in to out

	let udph = etherparse::UdpHeaderSlice::from_slice(&recv_buf[..len]).expect("could not parse rx udp header");
	let datai = udph.slice().len();
	let udp_payload = &recv_buf[datai..len];
	let udp_payload_bytes = len-datai;
	let mut udp = udph.to_header();

	// if udp dest port == 53 then outbound dns request
	// let it progress

	// if udp src port == 53 then its inbound response
	// parse the response, see if its one of the target domains, 
	// if it is then add the real response to the wan table, 
	// and change the response to use whats contained in dns cache. 

	if udp.destination_port == 53 { 
		//println!("outbound dns-> : \tsrc: {:?} dst: {:?} ",ip.source,ip.destination);
		let mut req_buffer = BytePacketBuffer::new();
		req_buffer.buf[..udp_payload_bytes].copy_from_slice(&udp_payload);
        let request = match hermes::dns::protocol::DnsPacket::from_buffer(&mut req_buffer) {
            Ok(x) => x,
            Err(e) => {
                println!("Failed to parse UDP outbound query packet: {:?}", e);
                hermes::dns::protocol::DnsPacket::new()
            }
        };
        //request.print();
	}

	if udp.source_port == 53 { 
		//println!("inbound  dns-> : \tsrc: {:?} dst: {:?} ",ip.source,ip.destination);
		let mut rsp_buffer = BytePacketBuffer::new();
		rsp_buffer.buf[..udp_payload_bytes].copy_from_slice(&udp_payload);
        let mut response = match hermes::dns::protocol::DnsPacket::from_buffer(&mut rsp_buffer) {
            Ok(x) => x,
            Err(e) => {
                println!("Failed to parse UDP inbound query packet: {:?}", e);
                hermes::dns::protocol::DnsPacket::new()
            }
        };
 
 		let mut ip_response: Ipv4Addr;
	 	let name = &response.questions[0].name;
	 	if let Some(mut packet) = cm.host_cache.lookup(name, QueryType::A) { 
	        let mut wan_records = Vec::new();
			match response.answers[0] {
	        	DnsRecord::A { ref domain, addr, .. } => {
	            	//println!("got dns resolution of interest: {}, ip: {} ", domain.to_string(), addr.to_string());
	            	wan_records.push(DnsRecord::A {
	                	domain: domain.to_string(),
	                	addr: addr,
	                	ttl: TransientTtl(180),
	            	});
	            	cm.wan_cache.store(&wan_records);
	            }
	            _ => {println!("no match on dns resolution of interest");}
	        }     

	        //rsp_buffer = BytePacketBuffer::new();
    	    rsp_buffer.pos = 0;
        	response.header.answers=1;
			response.header.write(&mut rsp_buffer);
			for question in &response.questions {
            	question.write(&mut rsp_buffer);
        	}
		
			//hermes package does not support compressed domain names in PDU so hand code answer part 
			let mut answer:[ u8; 16] = [0xc0,0x0c,0,1,0,1,0,0,1,22,0,4,0,0,0,0];
			match packet.answers[0] {
    			DnsRecord::A { ref domain, addr, .. } => {
        			answer[12..].copy_from_slice(&addr.octets());
		        	rsp_buffer.buf[rsp_buffer.pos..rsp_buffer.pos+16].copy_from_slice(&answer[..]); 
		        	rsp_buffer.pos = rsp_buffer.pos + 16;
		        	udp.length = rsp_buffer.pos as u16 + 8;
					udp.checksum = udp.calc_checksum_ipv4(&ip, &rsp_buffer.buf[..rsp_buffer.pos]).expect("failed to compute checksum");
					let mut unwritten = &mut send_buf[0..];
					udp.write(&mut unwritten).unwrap();
					unwritten[..rsp_buffer.pos].copy_from_slice(&rsp_buffer.buf[..rsp_buffer.pos]); 
					// 8 is udp header length
					return rsp_buffer.pos + 8;
        		}
        		_ => {println!("failed to match packet answer[0]");}
        	}
		}
	}

    // upd packet has not been processed prior in this function so 
    // write it and its payload out returning the len of the pdu (udp + payload)
	udp.checksum = udp.calc_checksum_ipv4(&ip, &udp_payload[..udp_payload_bytes])
        .expect("failed to compute checksum");

    let mut unwritten = &mut send_buf[0..];
    udp.write(&mut unwritten).unwrap();
    unwritten[..udp_payload_bytes].copy_from_slice(&udp_payload);   
	len
}

fn process_icmp(ip: &etherparse::Ipv4Header, _cm: &mut ConnectionManager, recv_buf: &[u8], len: usize, send_buf: &mut[u8]) -> usize { 
	// doing no processing at moment, just copy udp payload from in to out
	send_buf[..len].copy_from_slice(&recv_buf[..len]);
	len
}

fn recv_buffer(interface: &mut netif::Interface, mut recv_buf: &mut[u8]) -> usize { 
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

fn send_buffer(interface: &mut netif::Interface, send_buf: &[u8], len: usize) { 
	match interface.send(&send_buf[..len]) { 
		Ok(_n_sent) => { 
			//println!("wrote {} bytes", _n_sent) 
			//let iph = etherparse::Ipv4HeaderSlice::from_slice(&send_buf[UTUNHEADERLEN..len]).expect("could not parse tx ip header");
			//println!("-> : \tsrc: {} dst: {} len: {} proto: {} ",iph.source_addr(),iph.destination_addr(),len,iph.protocol());
		},
		Err(e) => println!("send function failed on {}: {:?}", interface.name(),e),
		}
}


fn main() {

	let mut cm = ConnectionManager::default();

	dnsresolv::initialize_caches(&mut cm.host_cache, &mut cm.wan_cache,&mut cm.nat_map);

	let _name = "utun1";
	#[cfg(target_os = "macos")]
	let mut interface = netif::Interface::new(mac_utun::get_utun().expect("Error, did not get a untun returned")); 
	#[cfg(target_os = "linux")]
	let mut interface = netif::Interface::new(tun_tap::Iface::new(_name, tun_tap::Mode::Tun).unwrap());

	loop {
	
	    let mut buf = [0u8; 2004];
	    let mut out = [0u8; 2004];
	    let len: usize;

		len = recv_buffer(&mut interface,&mut buf);

		// assuming this is ipv4 for the moment
		//let iph = etherparse::Ipv4HeaderSlice::from_slice(&buf[UTUNHEADERLEN..len]).expect("could not parse rx ip header");
        
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[UTUNHEADERLEN..len]) {
    	    Ok(iph) => {	
		        //println!("<- : \tsrc: {} dst: {} len: {} proto: {} ",iph.source_addr(),iph.destination_addr(),len,iph.protocol());
		        match iph.protocol() { 
			        0x01|0x06|0x11 => { 
			        	interface.pcap_write(&buf,len as u32);
			        	let outbuf_len = process_l3(&mut cm, &buf, len, &mut out);
			        	let iph = etherparse::Ipv4HeaderSlice::from_slice(& out[4..outbuf_len] as &[u8]).expect("could not parse tx ip header");
						//println!("L3-> : \tsrc: {} dst: {} len: {} proto: {} ",iph.source_addr(),iph.destination_addr(),outbuf_len,iph.protocol());
			       		//outbuf_len = process_tcp(&iph, &mut cm, &recv_buf, len, &mut send_buf);
			        	send_buffer(&mut interface, &mut out,outbuf_len);
			        	interface.pcap_write(&out,outbuf_len as u32);	
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
