use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, BorderType, Cell, Row, Table, Sparkline},
    Frame,
};
use crate::AppState;

pub fn render_ui(frame: &mut Frame, state: &AppState, interface: &str) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Status Bar
            Constraint::Length(10), // Analytics Dashboard
            Constraint::Min(0),     // Live Traffic Table
        ])
        .split(frame.area());

    // --- 1. Status Bar ---
    let status_text = format!(
        " 🌊 Vectura Engine | 🌐 Interface: {} | 📦 Total Packets: {} ",
        interface, state.total_packets
    );
    let status_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(status_text, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    frame.render_widget(status_block, main_chunks[0]);

    // --- 2. Analytics Dashboard ---
    let analytics_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[1]);

    // Top Flows (Left)
    let top_talkers = state.top_talkers();
    let talker_rows: Vec<Row> = top_talkers.iter().enumerate().map(|(i, (flow, bytes))| {
        Row::new(vec![
            Cell::from(format!(" #{} ", i + 1)).style(Style::default().fg(Color::DarkGray)),
            Cell::from(format!(" {} ", flow)).style(Style::default().fg(Color::LightCyan)),
            Cell::from(format!(" {} KB ", bytes / 1024)).style(Style::default().fg(Color::LightRed)),
        ])
    }).collect();

    let talker_table = Table::new(talker_rows, [Constraint::Length(5), Constraint::Min(35), Constraint::Min(10)])
        .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).title(" 🏆 Top Flows (Src ⟶ Dst) ").style(Style::default().fg(Color::Yellow)));
    frame.render_widget(talker_table, analytics_chunks[0]);

    // Live Bandwidth Graph (Right)
    let mbps = state.current_mbps;
    let speed_text = format!("{:.2} Mbps", mbps);
    
    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(Span::styled(
                    format!(" 🚀 Live Ingress Bandwidth ( {} ) ", speed_text),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().fg(Color::DarkGray)),
        )
        .data(&state.bandwidth_history)
        .style(Style::default().fg(Color::LightGreen));

    frame.render_widget(sparkline, analytics_chunks[1]);

    // --- 3. Live Traffic Table ---
    let available_rows = main_chunks[2].height.saturating_sub(3) as usize;
    let start_index = state.traffic_history.len().saturating_sub(available_rows);
    let visible_traffic = &state.traffic_history[start_index..];

    let sep_style = Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD);
    let sep_char = "┇"; 

    let rows: Vec<Row> = visible_traffic.iter().map(|data| {
        let proto_style = match data.protocol {
            17 => Style::default().fg(Color::Magenta), // UDP
            6 => Style::default().fg(Color::Yellow),   // TCP
            _ => Style::default().fg(Color::Gray),
        };
        let sep = Cell::from(sep_char).style(sep_style);
        let proto_combo = format!(" {} ({}) ", data.protocol, data.protocol_name());

        // Direction logic and bold coloring
        let dir_str = data.direction_symbol();
        let dir_style = if dir_str == "<--" {
            Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)
        };

        Row::new(vec![
            sep.clone(),
            Cell::from(format!(" {} ", data.timestamp)).style(Style::default().fg(Color::DarkGray)),
            sep.clone(),
            Cell::from(format!(" {} ", data.src_ip)).style(Style::default().fg(Color::LightCyan)),
            sep.clone(),
            Cell::from(format!(" {} ", data.src_port)).style(Style::default().fg(Color::DarkGray)),
            sep.clone(),
            Cell::from(format!(" {} ", dir_str)).style(dir_style),
            sep.clone(),
            Cell::from(format!(" {} ", data.dst_ip)).style(Style::default().fg(Color::LightGreen)),
            sep.clone(),
            Cell::from(format!(" {} ", data.dst_port)).style(Style::default().fg(Color::DarkGray)),
            sep.clone(),
            Cell::from(format!(" {} ", data.geo_location)).style(Style::default().fg(Color::Yellow)), // INJECTED GEO
            sep.clone(),
            Cell::from(proto_combo).style(proto_style),
            sep.clone(),
            Cell::from(format!(" {} B ", data.size)).style(Style::default().fg(Color::LightRed)),
            sep.clone(), 
        ])
    }).collect();

    // Added the Constraint::Min(7) for the Geo column
    let widths = [
        Constraint::Length(1), Constraint::Min(10), // Time
        Constraint::Length(1), Constraint::Min(16), // Src IP
        Constraint::Length(1), Constraint::Min(7),  // Src Port
        Constraint::Length(1), Constraint::Min(5),  // Dir
        Constraint::Length(1), Constraint::Min(16), // Dst IP
        Constraint::Length(1), Constraint::Min(7),  // Dst Port
        Constraint::Length(1), Constraint::Min(7),  // Geo
        Constraint::Length(1), Constraint::Min(18), // Protocol
        Constraint::Length(1), Constraint::Min(10), // Size
        Constraint::Length(1),
    ];

    let header = Row::new(vec![
        Cell::from(sep_char).style(sep_style),
        Cell::from(" Time"), Cell::from(sep_char).style(sep_style),
        Cell::from(" Source IP"), Cell::from(sep_char).style(sep_style),
        Cell::from(" Port"), Cell::from(sep_char).style(sep_style),
        Cell::from(" Dir"), Cell::from(sep_char).style(sep_style),
        Cell::from(" Destination IP"), Cell::from(sep_char).style(sep_style),
        Cell::from(" Port"), Cell::from(sep_char).style(sep_style),
        Cell::from(" Geo"), Cell::from(sep_char).style(sep_style), // INJECTED HEADER
        Cell::from(" Protocol"), Cell::from(sep_char).style(sep_style),
        Cell::from(" Size"), Cell::from(sep_char).style(sep_style),
    ]).style(Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD));

    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(0)
        .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::DarkGray)).title(" 📡 Packet Stream "));

    frame.render_widget(table, main_chunks[2]);
}