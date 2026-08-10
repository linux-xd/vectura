#![no_std]

#[cfg(feature = "user")]
use serde::{Serialize, Deserialize};

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PacketEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub ttl: u8,
    pub tcp_flags: u8,
    pub _pad: u8, // 1 byte padding for alignment
    pub size: u32,
}

// TCP Flag Masks
pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_URG: u8 = 0x20;
