


#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct FiveTuple {
    pub src: ([u8; 4], u16),
    pub dst: ([u8; 4], u16),
    pub protocol: u8,
}

impl Default for FiveTuple {
    fn default() -> Self { 
        FiveTuple { 
            src: ([0; 4], 0),
            dst: ([0; 4], 0),
            protocol: 0,
        } 
    }
}


#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Connection {
    pub id: u32,
    pub nat_addr: ([u8; 4],[u8; 4]),
    pub nat_port: (u16, u16),

}

impl Default for Connection { 
    fn default() -> Self { 
        Connection { id: 0, 
                    nat_addr: ([0; 4],[0; 4]),
                    nat_port: (0,0),
        }
    }
}

impl Connection { 
    #[allow(dead_code)]
	pub fn new() -> Self { 
		Connection { id: 0, nat_addr:([0; 4],[0; 4]),
					nat_port: (0,0)}
	}

}