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
    let eth_proto = ctx.load::<u16>(12).map_err(|_| ())?;
    
    // Check if it's an IPv4 packet (0x0800 in network byte order -> 8)
    if eth_proto != 8 {
        return Ok(()); 
    }

    // 2. Read IPv4 Header (starts at offset 14)
    let saddr = ctx.load::<u32>(14 + 12).map_err(|_| ())?;
    let daddr = ctx.load::<u32>(14 + 16).map_err(|_| ())?;
    let protocol = ctx.load::<u8>(14 + 9).map_err(|_| ())?;
    
    // Total packet length
    let length = ctx.len();

    // 3. Populate our shared struct
    let event = PacketEvent {
        saddr: u32::from_be(saddr),
        daddr: u32::from_be(daddr),
        sport: 0, // Port parsing requires deeper TCP/UDP header inspection
        dport: 0,
        protocol,
        length,
    };

    // 4. Fire the event across the bridge to user-space
    EVENTS.output(&ctx, &event, 0);

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}