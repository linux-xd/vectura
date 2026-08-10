use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, BorderType, Cell, Row, Table},
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

    // Modern Top Status Bar
    let status_text = format!(
        " 🌊 Vectura Engine | 🌐 Interface: {} | 📦 Total Packets: {} ",
        interface, total_packets
    );
    let status_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            status_text,
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
    frame.render_widget(status_block, chunks[0]);

    let available_rows = chunks[1].height.saturating_sub(3) as usize;
    let start_index = traffic_data.len().saturating_sub(available_rows);
    let visible_traffic = &traffic_data[start_index..];

    // Bold dashed separator for the btop aesthetic
    let sep_style = Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD);
    let sep_char = "┇"; 

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

            let proto_style = match proto_str.as_str() {
                p if p.contains("DNS") => Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                "TCP" => Style::default().fg(Color::Yellow),
                "UDP" => Style::default().fg(Color::Magenta),
                _ => Style::default().fg(Color::Gray),
            };

            let sep = Cell::from(sep_char).style(sep_style);

            Row::new(vec![
                sep.clone(),
                Cell::from(format!(" {} ", src_ip_str)).style(Style::default().fg(Color::LightCyan)),
                sep.clone(),
                Cell::from(format!(" {} ", src_port_str)).style(Style::default().fg(Color::DarkGray)),
                sep.clone(),
                Cell::from(format!(" {} ", dst_ip_str)).style(Style::default().fg(Color::LightGreen)),
                sep.clone(),
                Cell::from(format!(" {} ", dst_port_str)).style(Style::default().fg(Color::DarkGray)),
                sep.clone(),
                Cell::from(format!(" {} ", remote_str)).style(Style::default().fg(Color::LightBlue)),
                sep.clone(),
                Cell::from(format!(" {} ", proto_str)).style(proto_style),
                sep.clone(),
                Cell::from(format!(" {} ", size_str)).style(Style::default().fg(Color::LightRed)),
                sep.clone(), // Final right-side border
            ])
        })
        .collect();

    // Dynamic Spreading Layout (No filler columns)
    let widths = [
        Constraint::Length(1), // 0: ┇ (Far Left Border)
        Constraint::Min(16),   // 1: Src IP
        Constraint::Length(1), // 2: ┇
        Constraint::Min(7),    // 3: Src Port
        Constraint::Length(1), // 4: ┇
        Constraint::Min(16),   // 5: Dst IP
        Constraint::Length(1), // 6: ┇
        Constraint::Min(7),    // 7: Dst Port
        Constraint::Length(1), // 8: ┇
        Constraint::Min(16),   // 9: Target IP
        Constraint::Length(1), // 10: ┇
        Constraint::Min(9),    // 11: Protocol
        Constraint::Length(1), // 12: ┇
        Constraint::Min(10),   // 13: Size
        Constraint::Length(1), // 14: ┇ (Far Right Border)
    ];

    let header = Row::new(vec![
        Cell::from(sep_char).style(sep_style),
        Cell::from(" Source IP"),
        Cell::from(sep_char).style(sep_style),
        Cell::from(" Port"),
        Cell::from(sep_char).style(sep_style),
        Cell::from(" Destination IP"),
        Cell::from(sep_char).style(sep_style),
        Cell::from(" Port"),
        Cell::from(sep_char).style(sep_style),
        Cell::from(" Target IP"),
        Cell::from(sep_char).style(sep_style),
        Cell::from(" Protocol"),
        Cell::from(sep_char).style(sep_style),
        Cell::from(" Size"),
        Cell::from(sep_char).style(sep_style),
    ])
    .style(Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD));

    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(0) // Forces separators to stay crisp without gaps
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(Span::styled(
                    " 📡 Live Traffic ",
                    Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD),
                )),
        );

    frame.render_widget(table, chunks[1]);
}