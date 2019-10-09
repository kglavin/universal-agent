
// types in use

use std::net::Ipv4Addr;


#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct FiveTuple {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
    pub protocol: u8,
}



#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Connection {
    pub id: u32,
    pub nat_addr: (Ipv4Addr,Ipv4Addr),
    pub nat_port: (u16, u16),

}

impl Connection { 

	pub fn new() -> Self { 
		Connection { id: 0, 
					nat_addr: (Ipv4Addr::new(127,0,0,1),Ipv4Addr::new(127,0,0,1)),
					nat_port: (0,0)}
	}

}