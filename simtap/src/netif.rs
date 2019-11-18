// network interface abstraction using tun/tap as appropriate across the various platforms

use std::convert::TryInto;
use std::fs::File;
use pcap_file::{PcapWriter,PcapHeader,DataLink};

#[cfg(target_os = "macos")]
use std::net::UdpSocket;

#[cfg(target_os = "linux")]
use tun_tap;

trait NetworkInterface { 
	fn send(&mut self, buf: &[u8]) -> std::io::Result<usize>;
	fn recv(&self, mut buf: &mut[u8]) -> std::io::Result<usize>;
	fn name(&self) -> &str;
	fn pcap_write(&mut self, data: &[u8], orig_len: u32)-> std::io::Result<usize>;
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct MacosInterface {  
	socket: UdpSocket,
	name: String,
	pcap_file: PcapWriter<File>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxInterface { 
	netif: tun_tap::Iface,
	pcap_file: PcapWriter<File>,
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
		let file_out = File::create("/tmp/simtap.pcap").expect("Error creating file out");
		let header = PcapHeader {
		    magic_number : 0xa1b2c3d4,
		    version_major : 2,
		    version_minor : 4,
		    ts_correction : 0,
		    ts_accuracy : 0,
		    snaplen : 65535,
		    datalink : DataLink::NULL
		};
		let pcap_writer = PcapWriter::with_header(header,file_out).expect("Error writing file");
		let n = MacosInterface {
			socket: intf.0,
			name: intf.1,
			pcap_file: pcap_writer,
		};
		Interface { 
			nic: n,
			}
		}
#[cfg(target_os = "linux")]
	pub fn new(intf:tun_tap::Iface) -> Self {
		let file_out = File::create("/tmp/simtap.pcap").expect("Error creating file out");
		let header = PcapHeader {
		    magic_number : 0xa1b2c3d4,
		    version_major : 2,
		    version_minor : 4,
		    ts_correction : 0,
		    ts_accuracy : 0,
		    snaplen : 65535,
		    datalink : DataLink::NULL
		};
		let pcap_writer = PcapWriter::with_header(header,file_out).expect("Error writing file");
		let n = LinuxInterface {
			netif: intf,
			pcap_file: pcap_writer,
		};
		Interface { 
			nic: n,
			}
		}
	pub fn send(&mut self, buf: &[u8]) -> std::io::Result<usize> { 
		//self.nic.pcap_write(buf,buf.len() as u32);
		self.nic.send(buf)
	}
	pub fn recv(&mut self, mut buf: &mut[u8]) -> std::io::Result<usize> { 
		let res: std::io::Result<usize>; 
		match self.nic.recv(&mut buf) {  
			Ok(n) => {
				//self.nic.pcap_write(buf,n as u32);
				res = Ok(n);
			} 
			_ => {	res = Ok(0);
			} 
		}
		return res
	}
	pub fn name(&self) -> &str { 
		self.nic.name()
	}

	pub fn pcap_write(&mut self, data: &[u8], len: u32)-> std::io::Result<usize> { 
		self.nic.pcap_write(&data,len);
		Ok(len as usize)
	}

}

#[cfg(target_os = "macos")]
impl NetworkInterface for MacosInterface { 
	fn send(&mut self, buf: &[u8]) -> std::io::Result<usize> { 
		self.socket.send(buf)
	}
	fn recv(&self, mut buf: &mut[u8]) -> std::io::Result<usize> { 
		self.socket.recv(&mut buf)
	}
	fn name(&self) -> &str { 
		&self.name
	}
	fn pcap_write(&mut self,data: &[u8], orig_len: u32) -> std::io::Result<usize> {
		let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
		unsafe {
    		libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
		}
		self.pcap_file.write(ts.tv_sec.try_into().unwrap(),ts.tv_nsec.try_into().unwrap(),&data[..orig_len as usize]);
		Ok(orig_len as usize)
	} 
}

#[cfg(target_os = "linux")]
impl NetworkInterface for LinuxInterface { 
	fn send(&mut self, buf: &[u8]) -> std::io::Result<usize> { 
		self.netif.send(buf)
	}
	fn recv(&self, mut buf: &mut[u8]) -> std::io::Result<usize> { 
		self.netif.recv(&mut buf)
	}
	fn name(&self) -> &str { 
			self.netif.name()
	}
	fn pcap_write(&mut self,data: &[u8], orig_len: u32) -> std::io::Result<usize> {
		let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
		unsafe {
    		libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
		}
		self.pcap_file.write(ts.tv_sec.try_into().unwrap(),ts.tv_nsec.try_into().unwrap(),&data[..orig_len as usize]);
		Ok(orig_len as usize)
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
