
// module holding the network address translation from real ip to virtual ip and also 
// reverse direction translations within the host

// LRU Based map of 5 tuple flow to natting, statistics, state etc. 
use std::option::Option;

const CACHESIZE:usize = 1024;

pub struct NatMap {
	id: u32,
	cache: lru::LruCache<[u8; 4], [u8; 4]>,
}

impl NatMap {
	#[allow(dead_code)]
	pub fn new() -> Self { 
		NatMap { id: 123, cache: lru::LruCache::new(CACHESIZE) }
	}

	pub fn put(&mut self, key: [u8; 4],  val: [u8; 4] ){ 
		self.id = 124;
		self.cache.put(key,val);
	}

	pub fn get(&mut self, key: [u8; 4]) -> Option<&[u8; 4]>{ 
		self.id = 123;
		self.cache.get(&key)
	}

	#[allow(dead_code)]
	pub fn get_id(&mut self) -> u32 { 
		self.id
	}

	#[allow(dead_code)]
	pub fn is_empty(&mut self) -> bool { 
		self.cache.is_empty()
	}

	#[allow(dead_code)]
	pub fn len(&mut self) -> usize { 
		self.cache.len()
	}

	#[allow(dead_code)]
	pub fn clear(&mut self) { 
		self.cache.clear()
	}
}

impl Default for NatMap { 
    fn default() -> Self { 
        NatMap { id: 0, 
        	cache: lru::LruCache::new(CACHESIZE),
        }
    }
}