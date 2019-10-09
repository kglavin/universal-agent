
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct FiveTuple {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
    pub protocol: u8,
}

impl Default for FiveTuple {
    fn default() -> Self { 
        FiveTuple { 
            src: (Ipv4Addr::new(0,0,0,0), 0),
            dst: (Ipv4Addr::new(0,0,0,0), 0),
            protocol: 0,
        } 
    }
}


#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Connection {
    pub id: u32,
    pub nat_addr: (Ipv4Addr,Ipv4Addr),
    pub nat_port: (u16, u16),

}

impl Default for Connection { 
    fn default() -> Self { 
        Connection { id: 0, 
                    nat_addr: (Ipv4Addr::new(127,0,0,1),Ipv4Addr::new(127,0,0,1)),
                    nat_port: (0,0),
        }
    }
}

impl Connection { 
    #[allow(dead_code)]
	pub fn new() -> Self { 
		Connection { id: 0, 
					nat_addr: (Ipv4Addr::new(127,0,0,1),Ipv4Addr::new(127,0,0,1)),
					nat_port: (0,0)}
	}

}