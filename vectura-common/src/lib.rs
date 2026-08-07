#![no_std]

#[cfg(feature = "user")]
use serde::{Serialize, Deserialize};

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PacketEvent {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub length: u32,
}
