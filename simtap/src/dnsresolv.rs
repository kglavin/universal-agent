// Provide dns resolution, interception and caching services


//use hermes::dns;


use hermes::dns::client::DnsClient; 
use hermes::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode,TransientTtl};
use hermes::dns::cache::Cache;
use crate::nat::NatMap;
use std::net::Ipv4Addr;


pub struct DNSCache { 
	cache: hermes::dns::cache::Cache,
}

impl DNSCache { 
	pub fn new() -> Self {
		let cache = Cache::new();
		DNSCache { 
			cache: cache
		}
	}

	pub fn lookup(&mut self, qname: &str, qtype: QueryType) -> Option<DnsPacket>  {
		self.cache.lookup(qname, qtype)
	}

	pub fn store(&mut self, records: &[DnsRecord]) {
		self.cache.store(records)
	}

	pub fn store_nxdomain(&mut self, qname: &str, qtype: QueryType, ttl: u32) {
		self.cache.store_nxdomain(qname, qtype, ttl)
	}

}

impl Default for DNSCache { 
    fn default() -> Self { 
        DNSCache {
            cache: Cache::new(),
        }
    }
}


 pub fn initialize_caches( host_cache: &mut DNSCache,  wan_cache: &mut DNSCache, nat_map: & mut NatMap) { 
 #[cfg(target_os = "macos")]
    let mut rdr = csv::Reader::from_path("/Users/kglavin/Documents/GitHub/universal-agent/simtap/domains.csv").unwrap();
 #[cfg(target_os = "linux")]
    let mut rdr = csv::Reader::from_path("./domains.csv").unwrap();
    let mut dns_records = Vec::new();
    let mut wan_records = Vec::new();
     
    let mut ip_a: Ipv4Addr; 
    let mut ip_b: Ipv4Addr;

    use hermes::dns::client::{DnsNetworkClient};
    let client = DnsNetworkClient::new(31999);
    client.run().unwrap();
    for result in rdr.records() {
        let record = result.unwrap();
        ip_a = record[1].parse().unwrap();
        dns_records.push(DnsRecord::A {
            domain: record[0].to_string(),
            addr: record[1].parse().unwrap(),
            ttl: TransientTtl(600),
        });

        println!("dns - name: {}, ip: {} ", &record[0], &record[1]);

        
 #[cfg(target_os = "macos")]
        let res = client
            .send_udp_query(&record[0].to_string(), QueryType::A, ("8.8.8.8", 53), true)
            .unwrap();
 #[cfg(target_os = "linux")]
        let res = client
            .send_udp_query(&record[0].to_string(), QueryType::A, ("44.1.13.1", 53), true)
            .unwrap();

        match res.answers[0] {
            DnsRecord::A { ref domain, addr, .. } => {
                println!("wan - name: {}, ip: {} ", domain.to_string(), addr.to_string());
                ip_b = addr;
                wan_records.push(DnsRecord::A {
                    domain: domain.to_string(),
                    addr: addr,
                    ttl: TransientTtl(3600),
                });                            
            }
            _ => panic!(),
        }
        nat_map.put(ip_a.octets(),ip_b.octets());
        nat_map.put(ip_b.octets(),ip_a.octets());

        match nat_map.get(ip_a.octets()) { 
                Some(ip) => {
                    println!("nat_map - A: {:?}, ip_b: {:?} ", ip_a, ip);
                },
                None => { assert!(false, "failed to get nat mapping ip_a->ip_b for {:?} ", ip_a);},
        } 

        match nat_map.get(ip_b.octets()) { 
                Some(ip) => {
                    println!("nat_map - B: {:?}, ip_a: {:?} ", ip_b, ip);
                },
                None => { assert!(false, "failed to get nat mapping ip_b->ip_a for {:?} ", ip_b);},
        } 
    }
    host_cache.store(&dns_records);
    wan_cache.store(&wan_records);

 }


#[cfg(test)]
mod tests {
	use super::*;
#[test]
	fn create_cache() {
		let mut dns_cache  = DNSCache::new();

		if dns_cache.lookup("www.google.com", QueryType::A).is_some() {
    		panic!()
    	}

    	// Register a negative cache entry
    	dns_cache.store_nxdomain("www.google.com", QueryType::A, 3600);

    	// Verify that we get a response, with the NXDOMAIN flag set
    	if let Some(packet) = dns_cache.lookup("www.google.com", QueryType::A) {
       		assert_eq!(ResultCode::NXDOMAIN, packet.header.rescode);
    	}


        // Now add some actual records
        let mut records = Vec::new();
        records.push(DnsRecord::A {
            domain: "www.google.com".to_string(),
            addr: "127.0.0.1".parse().unwrap(),
            ttl: TransientTtl(3600),
        });
        records.push(DnsRecord::A {
            domain: "www.yahoo.com".to_string(),
            addr: "127.0.0.2".parse().unwrap(),
            ttl: TransientTtl(0),
        });
        records.push(DnsRecord::CNAME {
            domain: "www.microsoft.com".to_string(),
            host: "www.somecdn.com".to_string(),
            ttl: TransientTtl(3600),
        });

        dns_cache.store(&records);

        if let Some(packet) = dns_cache.lookup("www.google.com", QueryType::A) {
            assert_eq!(ResultCode::NOERROR, packet.header.rescode);
        }


    	println!("ran dnsresolv::create_cache")
    }
#[test]
    fn csv_dns() { 
        let _dns_cache  = DNSCache::new();
        let mut rdr = csv::Reader::from_path("/Users/kglavin/Documents/GitHub/universal-agent/simtap/domains.csv").unwrap();
        for result in rdr.records() {
            let record = result.unwrap();
            println!("{:?}", record);
        }
    }
}

