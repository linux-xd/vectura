#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};
use vectura_common::{
    PacketEvent, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN, TCP_FLAG_URG,
};

#[map]
static mut EVENTS: PerfEventArray<PacketEvent> = PerfEventArray::new(0);

const ETH_HLEN: usize = 14;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

#[classifier]
pub fn vectura_ingress(ctx: TcContext) -> i32 {
    match try_vectura_ingress(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // 0 translates to TC_ACT_OK in the kernel
    }
}

fn try_vectura_ingress(ctx: &TcContext) -> Result<i32, ()> {
    let eth_type: u16 = ctx.load(12).map_err(|_| ())?;
    if u16::from_be(eth_type) != 0x0800 {
        return Ok(0);
    }

    let version_ihl: u8 = ctx.load(ETH_HLEN).map_err(|_| ())?;
    let ihl = (version_ihl & 0x0F) as usize * 4;
    if ihl < 20 {
        return Ok(0);
    }

    let ttl: u8 = ctx.load(ETH_HLEN + 8).map_err(|_| ())?;
    let protocol: u8 = ctx.load(ETH_HLEN + 9).map_err(|_| ())?;
    let src_ip: u32 = ctx.load(ETH_HLEN + 12).map_err(|_| ())?;
    let dst_ip: u32 = ctx.load(ETH_HLEN + 16).map_err(|_| ())?;

    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let mut tcp_flags: u8 = 0;

    let l4_offset = ETH_HLEN + ihl;

    if protocol == IP_PROTO_TCP {
        src_port = u16::from_be(ctx.load(l4_offset).map_err(|_| ())?);
        dst_port = u16::from_be(ctx.load(l4_offset + 2).map_err(|_| ())?);
        tcp_flags = ctx.load(l4_offset + 13).map_err(|_| ())?;
        
        // Suppress unused import warnings for the flags
        let _ = TCP_FLAG_ACK | TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_RST | TCP_FLAG_SYN | TCP_FLAG_URG;
    } else if protocol == IP_PROTO_UDP {
        src_port = u16::from_be(ctx.load(l4_offset).map_err(|_| ())?);
        dst_port = u16::from_be(ctx.load(l4_offset + 2).map_err(|_| ())?);
    }

    let packet_size = ctx.len();

    let event = PacketEvent {
        src_ip: u32::from_be(src_ip),
        dst_ip: u32::from_be(dst_ip),
        src_port,
        dst_port,
        protocol,
        ttl,
        tcp_flags,
        _pad: 0,
        size: packet_size,
    };

    unsafe {
        EVENTS.output(ctx, &event, 0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}