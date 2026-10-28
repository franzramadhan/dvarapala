/// Bounds-checked reads at an offset into a packet. A slice in userspace,
/// the `xdp_md` data pointers in the program, so the kernel verifier sees
/// a check against the packet end before every access.
pub trait Bytes {
    /// `N` bytes at `off`, `None` past the end.
    fn get<const N: usize>(&self, off: usize) -> Option<[u8; N]>;
}

impl Bytes for [u8] {
    fn get<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        self.get(off..off.checked_add(N)?)?.try_into().ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// `syn`: SYN without ACK, a new connection attempt.
    Tcp {
        syn: bool,
    },
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    /// IPv6, or IPv4 mapped to `::ffff:a.b.c.d`.
    pub src: [u8; 16],
    pub v4: bool,
    pub proto: Proto,
    pub dst_port: u16,
}

const ETH_LEN: usize = 14;
const VLAN_LEN: usize = 4;
const MAX_VLANS: usize = 2;
const MAX_EXT: usize = 4;

/// The source, protocol and destination port of a TCP or UDP packet in an
/// Ethernet frame, through up to two VLAN tags and four IPv6 extension
/// headers. `None` for anything else, a truncated header or a fragment
/// after the first: "not ours", the program passes it.
pub fn parse<B: Bytes + ?Sized>(b: &B) -> Option<Packet> {
    let mut off = ETH_LEN;
    let mut ether = u16::from_be_bytes(b.get(12)?);
    for _ in 0..MAX_VLANS {
        if ether != 0x8100 && ether != 0x88a8 {
            break;
        }
        ether = u16::from_be_bytes(b.get(off + 2)?);
        off += VLAN_LEN;
    }
    let mut src = [0u8; 16];
    let (proto, l4, v4) = match ether {
        0x0800 => {
            let [vihl] = b.get::<1>(off)?;
            let ihl = usize::from(vihl & 0x0f) * 4;
            if vihl >> 4 != 4 || ihl < 20 {
                return None;
            }
            let frag = u16::from_be_bytes(b.get(off + 6)?);
            if frag & 0x1fff != 0 {
                return None;
            }
            let [proto] = b.get::<1>(off + 9)?;
            let a: [u8; 4] = b.get(off + 12)?;
            src[10] = 0xff;
            src[11] = 0xff;
            src[12..].copy_from_slice(&a);
            (proto, off + ihl, true)
        }
        0x86dd => {
            let [v] = b.get::<1>(off)?;
            if v >> 4 != 6 {
                return None;
            }
            let [mut next] = b.get::<1>(off + 6)?;
            src = b.get(off + 8)?;
            let mut l4 = off + 40;
            for _ in 0..MAX_EXT {
                match next {
                    // hop-by-hop, routing, destination options
                    0 | 43 | 60 => {
                        let [n, len] = b.get::<2>(l4)?;
                        next = n;
                        l4 += (usize::from(len) + 1) * 8;
                    }
                    44 => {
                        let [n, _, hi, lo] = b.get::<4>(l4)?;
                        if u16::from_be_bytes([hi, lo]) >> 3 != 0 {
                            return None;
                        }
                        next = n;
                        l4 += 8;
                    }
                    _ => break,
                }
            }
            (next, l4, false)
        }
        _ => return None,
    };
    let dst_port = u16::from_be_bytes(b.get(l4 + 2)?);
    let proto = match proto {
        6 => {
            let [flags] = b.get::<1>(l4 + 13)?;
            Proto::Tcp {
                syn: flags & 0x12 == 0x02,
            }
        }
        17 => {
            b.get::<8>(l4)?;
            Proto::Udp
        }
        _ => return None,
    };
    Some(Packet {
        src,
        v4,
        proto,
        dst_port,
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use super::*;

    fn eth(ether: u16) -> Vec<u8> {
        let mut p = std::vec![0u8; 12];
        p.extend(ether.to_be_bytes());
        p
    }

    fn ipv4(proto: u8, options: usize) -> Vec<u8> {
        let mut h = std::vec![0u8; 20 + options];
        h[0] = 0x40 | ((20 + options) / 4) as u8;
        h[9] = proto;
        h[12..16].copy_from_slice(&[192, 0, 2, 7]);
        h
    }

    fn tcp(port: u16, flags: u8) -> Vec<u8> {
        let mut h = std::vec![0u8; 20];
        h[2..4].copy_from_slice(&port.to_be_bytes());
        h[13] = flags;
        h
    }

    fn udp(port: u16) -> Vec<u8> {
        let mut h = std::vec![0u8; 8];
        h[2..4].copy_from_slice(&port.to_be_bytes());
        h
    }

    fn v4_src() -> [u8; 16] {
        let mut a = [0u8; 16];
        a[10..].copy_from_slice(&[0xff, 0xff, 192, 0, 2, 7]);
        a
    }

    // RFC 0011 case 1
    #[test]
    fn tcp_syn_over_ipv4() {
        let p = [eth(0x0800), ipv4(6, 0), tcp(8080, 0x02)].concat();
        assert_eq!(
            parse(&p[..]),
            Some(Packet {
                src: v4_src(),
                v4: true,
                proto: Proto::Tcp { syn: true },
                dst_port: 8080
            })
        );
        let ack = [eth(0x0800), ipv4(6, 0), tcp(8080, 0x12)].concat();
        assert_eq!(parse(&ack[..]).unwrap().proto, Proto::Tcp { syn: false });
    }

    #[test]
    fn ipv4_options_and_vlan_tags() {
        // two tags: 802.1ad outer, 802.1Q inner
        let mut p = eth(0x88a8);
        p.extend([0, 1, 0x81, 0x00, 0, 2, 0x08, 0x00]);
        p.extend(ipv4(17, 8));
        p.extend(udp(443));
        let got = parse(&p[..]).unwrap();
        assert_eq!((got.proto, got.dst_port), (Proto::Udp, 443));
    }

    #[test]
    fn ipv6_extension_headers() {
        let mut ip = std::vec![0u8; 40];
        ip[0] = 0x60;
        ip[6] = 0; // hop-by-hop
        ip[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let mut hop = std::vec![0u8; 16];
        hop[0] = 44; // then a first fragment
        hop[1] = 1;
        let frag = [6u8, 0, 0, 0, 0, 0, 0, 0];
        let p = [
            eth(0x86dd),
            ip.clone(),
            hop.clone(),
            frag.to_vec(),
            tcp(8080, 0x02),
        ]
        .concat();
        let got = parse(&p[..]).unwrap();
        assert!(!got.v4);
        assert_eq!(got.src, ip[8..24]);
        assert_eq!(got.dst_port, 8080);
        // a later fragment carries no port
        let later = [6u8, 0, 0, 8, 0, 0, 0, 0];
        let p = [eth(0x86dd), ip, hop, later.to_vec(), tcp(8080, 0x02)].concat();
        assert_eq!(parse(&p[..]), None);
    }

    #[test]
    fn not_ours() {
        // ARP, ICMP, a later IPv4 fragment, a bad IHL
        assert_eq!(parse(&eth(0x0806)[..]), None);
        let icmp = [eth(0x0800), ipv4(1, 0), std::vec![0; 8]].concat();
        assert_eq!(parse(&icmp[..]), None);
        let mut frag = [eth(0x0800), ipv4(6, 0), tcp(80, 2)].concat();
        frag[ETH_LEN + 7] = 1;
        assert_eq!(parse(&frag[..]), None);
        let mut ihl = [eth(0x0800), ipv4(6, 0), tcp(80, 2)].concat();
        ihl[ETH_LEN] = 0x44;
        assert_eq!(parse(&ihl[..]), None);
    }

    #[test]
    fn every_truncation_is_none() {
        let p = [eth(0x0800), ipv4(6, 4), tcp(8080, 0x02)].concat();
        for n in 0..p.len() - 6 {
            assert_eq!(parse(&p[..n]), None, "{n} bytes");
        }
        assert!(parse(&p[..]).is_some());
    }
}
