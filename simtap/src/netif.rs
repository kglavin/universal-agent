// network interface abstraction using tun/tap as appropriate across the various platforms

#[cfg(target_os = "macos")]
use std::net::UdpSocket;

#[cfg(target_os = "linux")]
use tun_tap;


#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct MacosInterface {  
	fd: UdpSocket,
	if_name: String,
}

#[cfg(target_os = "macos")]
impl MacosInterface { 

	pub fn new(intf:(UdpSocket, String)) -> MacosInterface { 
		MacosInterface {
			fd: intf.0,
			if_name: intf.1,
		}
	}

	pub fn send(&self, buf: &[u8]) -> std::io::Result<usize> { 
		self.fd.send(buf)
	}

	pub fn recv(&self, mut buf: &mut [u8]) -> std::io::Result<usize> { 
		self.fd.recv(&mut buf)
	}

	pub fn name(&self) -> &str { 
		&self.if_name
	}
}

#[cfg(target_os = "linux")]
struct LinuxInterface { 
	netif: tun_tap::Iface,
}

#[cfg(target_os = "linux")]
pub impl LinuxInterface { 
	pub fn new(intf:tun_tap::Iface) -> LinuxInterface { 
		LinuxInterface {
			netif: intf,
		}
	}
	pub fn send(&self, buf: &[u8]) -> std::io::Result<usize> { 
		self.netif.send(buf)
	}
	pub fn recv(&self, buf: &mut[u8]) -> std::io::Result<usize> { 
		self.netif.recv(&mut buf)
	}
	pub fn name(&self) -> &str { 
			self.netif.name()
	}

}

#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct Interface<MacosInterface> {
	nic: MacosInterface,
}

#[cfg(target_os = "macos")]
impl Interface<MacosInterface> {

	pub fn new(nic: MacosInterface) -> Self {
		Interface { 
			nic: nic,
			}
		}

	pub fn send(&self, buf: &[u8]) -> std::io::Result<usize> { 
		self.nic.send(buf)
	}

	pub fn recv(&self, mut buf: & mut[u8]) -> std::io::Result<usize> { 
		self.nic.recv(&mut buf)
	}
	pub fn name(&self) -> &str { 
			self.nic.name()
	}

   }


#[cfg(target_os = "linux")]
pub struct Interface<LinuxInterface> {
	nic: LinuxInterface,
}






#[cfg(test)]
mod tests {
	use super::*;
#[test]

#[cfg(target_os = "macos")]
    fn test_1_macos() {
		let (fd,if_name) = mac_utun::get_utun().expect("Error, did not get a untun returned");
		let a = MacosInterface { fd, if_name } ;
    	let b = Interface::new(a);

    	println!("fd = {:?}",b.nic.fd);
    	assert_eq!(b.nic.if_name, b.nic.if_name)

    }
#[cfg(target_os = "linux")]
    fn test_1_linux() {
    	let name = "utun1";
    	let netif = tun_tap::Iface::without_packet_info(name, tun_tap::Mode::Tun)?;

    	let a = LinuxInterface { netif } ;
    	let b = Interface::new(a);
    }




}