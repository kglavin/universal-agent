// network interface abstraction using tun/tap as appropriate across the various platforms

#[cfg(target_os = "macos")]
use std::net::UdpSocket;
#[cfg(target_os = "linux")]
use tun_tap;

trait NetworkInterface { 
	fn send(&self, buf: &[u8]) -> std::io::Result<usize>;
	fn recv(&self, buf: &mut[u8]) -> std::io::Result<usize>;
	fn name(&self) -> &str;
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct MacosInterface {  
	socket: UdpSocket,
	name: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxInterface { 
	netif: tun_tap::Iface,
}

#[derive(Debug)]
pub struct Interface {
#[cfg(target_os = "linux")]
	nic: LinuxInterface,
#[cfg(target_os = "macos")]
	nic: MacosInterface,
}

impl Interface {
#[cfg(target_os = "macos")]
	pub fn new(intf:(UdpSocket, String)) -> Self {
		let n = MacosInterface {
			socket: intf.0,
			name: intf.1,
		};
		Interface { 
			nic: n,
			}
		}
#[cfg(target_os = "linux")]
	pub fn new(intf:tun_tap::Iface) -> Self {
		let n = LinuxInterface {
			netif: intf,
		};
		Interface { 
			nic: n,
			}
		}
	pub fn send(&self, buf: &[u8]) -> std::io::Result<usize> { 
		self.nic.send(buf)
	}
	pub fn recv(&self, mut buf: &mut[u8]) -> std::io::Result<usize> { 
		self.nic.recv(&mut buf)
	}
	pub fn name(&self) -> &str { 
			self.nic.name()
	}

}




#[cfg(target_os = "macos")]
impl NetworkInterface for MacosInterface { 
	fn send(&self, buf: &[u8]) -> std::io::Result<usize> { 
		self.socket.send(buf)
	}
	fn recv(&self, mut buf: &mut[u8]) -> std::io::Result<usize> { 
		self.socket.recv(&mut buf)
	}
	fn name(&self) -> &str { 
		&self.name
	}
}




#[cfg(target_os = "linux")]
impl NetworkInterface for LinuxInterface { 
	fn send(&self, buf: &[u8]) -> std::io::Result<usize> { 
		self.netif.send(buf)
	}
	fn recv(&self, mut buf: &mut[u8]) -> std::io::Result<usize> { 
		self.netif.recv(&mut buf)
	}
	fn name(&self) -> &str { 
			self.netif.name()
	}

}


#[cfg(test)]
mod tests {
	use super::*;
#[test]

#[cfg(target_os = "macos")]
    fn test_1_macos() {
		let a = mac_utun::get_utun().expect("Error, did not get a untun returned");
    	let b = Interface::new(a);

    	println!("interface name  = {:?}",b.nic.name());
    	assert_eq!(b.nic.name(), b.nic.name())

    }
#[cfg(target_os = "linux")]
    fn test_1_linux() {
    	let name = "utun1";
    	let netif = tun_tap::Iface::without_packet_info(name, tun_tap::Mode::Tun)?;
    	let b = Interface::new(netif);
   		println!("interface name  = {:?}",b.nic.name());
    	assert_eq!(b.nic.name(), b.nic.name())

    }




}