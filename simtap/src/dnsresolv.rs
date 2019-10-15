// Provide dns resolution, interception and caching services


//use hermes::dns;

use hermes::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode,TransientTtl};
use hermes::dns::cache::Cache;


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

    	println!("ran dnsresolv::create_cache")
    }
}