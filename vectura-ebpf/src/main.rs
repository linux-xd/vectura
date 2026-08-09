#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};
use core::mem;
use vectura_common::PacketEvent;

// The memory-safe bridge to send events to user-space
#[map]
static EVENTS: PerfEventArray<PacketEvent> = PerfEventArray::new(0);

#[classifier]
pub fn vectura_ingress(ctx: TcContext) -> i32 {
    match try_vectura_ingress(ctx) {
        Ok(_) => TC_ACT_PIPE,
        Err(_) => TC_ACT_PIPE, // Always allow traffic through, even if parsing fails
    }
}

// Minimal safe parsing skeleton for IPv4
fn try_vectura_ingress(ctx: TcContext) -> Result<(), ()> {
    // 1. Read Ethernet Header (14 bytes)
    let eth_proto = u16::from_be(ctx.load::<u16>(12).map_err(|_| ())?);
    
    // Check if it's an IPv4 packet (0x0800)
    if eth_proto != 0x0800 {
        return Ok(()); 
    }

    // 2. Read IPv4 Header
    let saddr = ctx.load::<u32>(14 + 12).map_err(|_| ())?;
    let daddr = ctx.load::<u32>(14 + 16).map_err(|_| ())?;
    let protocol = ctx.load::<u8>(14 + 9).map_err(|_| ())?;
    
    // Calculate IP Header Length (IHL) to find where L4 (TCP/UDP) starts
    let ihl_byte = ctx.load::<u8>(14).map_err(|_| ())?;
    let ihl = (ihl_byte & 0x0F) * 4;
    let l4_offset = 14 + ihl as usize;

    let mut sport = 0;
    let mut dport = 0;

    // 3. Parse TCP (6) or UDP (17) Ports
    if protocol == 6 || protocol == 17 {
        sport = u16::from_be(ctx.load::<u16>(l4_offset).unwrap_or(0));
        dport = u16::from_be(ctx.load::<u16>(l4_offset + 2).unwrap_or(0));
    }

    let length = ctx.len();

    // 4. Populate shared struct
    let event = PacketEvent {
        saddr: u32::from_be(saddr),
        daddr: u32::from_be(daddr),
        sport,
        dport,
        protocol,
        length,
    };

    // 5. Fire event to user-space
    EVENTS.output(&ctx, &event, 0);

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}