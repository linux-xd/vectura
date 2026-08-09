use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table},
    Frame,
};
use std::net::Ipv4Addr;
use vectura_common::PacketEvent;

pub struct TrafficRow {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub protocol: u8,
    pub size: u32,
}

impl From<PacketEvent> for TrafficRow {
    fn from(event: PacketEvent) -> Self {
        Self {
            src_ip: Ipv4Addr::from(event.saddr),
            src_port: event.sport,
            dst_ip: Ipv4Addr::from(event.daddr),
            dst_port: event.dport,
            protocol: event.protocol,
            size: event.length,
        }
    }
}

impl TrafficRow {
    fn is_private(ip: &Ipv4Addr) -> bool {
        ip.is_private() || ip.is_loopback()
    }

    pub fn remote_target(&self) -> String {
        if !Self::is_private(&self.src_ip) {
            format!("{}", self.src_ip)
        } else if !Self::is_private(&self.dst_ip) {
            format!("{}", self.dst_ip)
        } else {
            "LAN / NAT Internal".to_string()
        }
    }

pub fn protocol_name(&self) -> String {
        if self.src_port == 53 || self.dst_port == 53 {
            "DNS (53)".to_string()
        } else {
            match self.protocol {
                6 => "TCP".to_string(),
                17 => "UDP".to_string(),
                1 => "ICMP".to_string(),
                _ => format!("{}", self.protocol),
            }
        }
    }
}

pub fn render_ui(frame: &mut Frame, traffic_data: &[TrafficRow], total_packets: u64, interface: &str) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(frame.area());

    let status_text = format!(
        " Vectura Engine | Interface: {} | Total Packets: {} ",
        interface, total_packets
    );
    let status_block = Block::default()
        .borders(Borders::ALL)
        .title(status_text)
        .style(Style::default().fg(Color::Green));
    frame.render_widget(status_block, chunks[0]);

    // Calculate how many rows can actually fit in the table area
    let available_rows = chunks[1].height.saturating_sub(3) as usize;

    // Slice the traffic data to only take the newest packets that fit on screen
    let start_index = traffic_data.len().saturating_sub(available_rows);
    let visible_traffic = &traffic_data[start_index..];

    let rows: Vec<Row> = visible_traffic
        .iter()
        .map(|data| {
            let src_ip_str = data.src_ip.to_string();
            let src_port_str = data.src_port.to_string();
            let dst_ip_str = data.dst_ip.to_string();
            let dst_port_str = data.dst_port.to_string();
            let proto_str = data.protocol_name();
            let remote_str = data.remote_target();
            let size_str = format!("{} B", data.size);

            let proto_style = if proto_str.contains("DNS") {
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Yellow)
            };

            Row::new(vec![
                Cell::from(src_ip_str).style(Style::default().fg(Color::White)),
                Cell::from(src_port_str).style(Style::default().fg(Color::DarkGray)),
                Cell::from(dst_ip_str).style(Style::default().fg(Color::White)),
                Cell::from(dst_port_str).style(Style::default().fg(Color::DarkGray)),
                Cell::from(remote_str).style(Style::default().fg(Color::Green)),
                Cell::from(proto_str).style(proto_style),
                Cell::from(size_str).style(Style::default().fg(Color::Magenta)),
            ])
        })
        .collect();

    // Responsive 7-column layout totaling 100%
    let widths = [
        Constraint::Percentage(18), // Source IP
        Constraint::Percentage(7),  // Src Port
        Constraint::Percentage(18), // Destination IP
        Constraint::Percentage(7),  // Dst Port
        Constraint::Percentage(25), // Public Target
        Constraint::Percentage(13), // Protocol
        Constraint::Percentage(12), // Size
    ];

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "Source IP", 
                "Port", 
                "Destination IP", 
                "Port", 
                "Target IP", 
                "Protocol", 
                "Size"
            ])
            .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL).title(" Live Traffic "));

    frame.render_widget(table, chunks[1]);
}