
// LRU Based map of 5 tuple flow to natting, statistics, state etc. 
use std::option::Option;
use std::net::Ipv4Addr;

use crate::types::{FiveTuple, Connection};

const CACHESIZE:usize = 500;
 
pub struct FlowMap {
	id: u32,
	cache: lru::LruCache<FiveTuple, Connection>,
}


impl FlowMap { 
	pub fn new() -> Self { 
		FlowMap { id: 123, cache: lru::LruCache::new(CACHESIZE) }
	}

	pub fn put(&mut self, flow: crate::types::FiveTuple,  connection: crate::types::Connection ){ 
		self.id = 124;
		self.cache.put(flow,connection);
	}

	pub fn get(&mut self, flow: crate::types::FiveTuple) -> Option<&crate::types::Connection>{ 
		self.id = 123;
		self.cache.get(&flow)
	}

	pub fn get_id(&mut self) -> u32 { 
		self.id
	}

	pub fn is_empty(&mut self) -> bool { 
		self.cache.is_empty()
	}

	pub fn len(&mut self) -> usize { 
		self.cache.len()
	}

	pub fn clear(&mut self) { 
		self.cache.clear()
	}

}

#[cfg(test)]
mod tests {
	use super::*;

#[test]
    fn test_init() {
    	let mut fm = FlowMap::new();
        assert_eq!(fm.get_id(), 123);
    }


#[test]
    fn test_add_1() {
    	let mut fm = FlowMap::new();
    	let mut c = Connection::new();
    	let ft1 =  crate::types::FiveTuple {
       		src: (Ipv4Addr::new(127,0,0,1), 1),
       		dst: (Ipv4Addr::new(127,0,0,2), 2),
      		protocol: 0x6, };
      	let ft2 =  crate::types::FiveTuple {
       		src: (Ipv4Addr::new(127,0,0,3), 3),
       		dst: (Ipv4Addr::new(127,0,0,4), 4),
      		protocol: 0x6, };
      	let ft3 =  crate::types::FiveTuple {
       		src: (Ipv4Addr::new(127,0,0,5), 5),
       		dst: (Ipv4Addr::new(127,0,0,6), 6),
      		protocol: 0x6, };
      	let ft4 =  crate::types::FiveTuple {
       		src: (Ipv4Addr::new(127,0,0,7), 5),
       		dst: (Ipv4Addr::new(127,0,0,6), 6),
      		protocol: 0x6, };

      	assert!(fm.is_empty());
      	assert_eq!(fm.len(), 0);

    	c.id = 1;
  		fm.put(ft1,c);
  		assert_eq!(fm.len(), 1);

  		c.id = 2;
		fm.put(ft2,c);
		assert_eq!(fm.len(), 2);


		c.id = 3;
		fm.put(ft3,c);
		assert_eq!(fm.len(), 3);

		match fm.get(ft1) { 
			Some(con) => {
				assert_eq!(con.id, 1);
			},
			None => { assert!(false, "failed to get ft1");},
		}
		assert_eq!(fm.len(), 3 as usize);

		match fm.get(ft3) { 
			Some(con) => {
				assert_eq!(con.id, 3);
			},
			None => { assert!(false, "failed to get ft3");},
		}
		assert_eq!(fm.len(), 3 as usize);

		match fm.get(ft2) { 
			Some(con) => {
				assert_eq!(con.id, 2);
			},
			None => { assert!(false, "failed to get ft2");},
		}
		assert_eq!(fm.len(), 3 as usize);

		match fm.get(ft4) { 
			Some(_con) => {
				assert!(false, "should have not found ft4");
			},
			None => { assert!(true, "failed to get ft4");},
		}
		assert_eq!(fm.len(), 3 as usize);

		fm.clear();

		match fm.get(ft1) { 
			Some(_con) => {
				assert!(false, "should have not found ft1");
			},
			None => { assert!(true, "failed to get ft1");},
		}
		assert_eq!(fm.len(), 0 as usize);




    }

}