use aya::{
    include_bytes_aligned,
    maps::perf::{PerfEvent, PerfEventArray},
    programs::{tc, SchedClassifier, TcAttachType},
    util::online_cpus,
    Ebpf,
};
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use log::info;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Terminal,
};
use std::{collections::VecDeque, net::Ipv4Addr, time::Duration};
use tokio::sync::mpsc;
use vectura_common::PacketEvent;

#[derive(Parser, Debug)]
#[command(name = "vectura", about = "Type & Memory Safe eBPF Network Analyzer", version = "0.1.0")]
struct Cli {
    #[arg(short, long, default_value = "eth0")]
    interface: String,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Server {
        #[arg(short, long, default_value = "3000")]
        port: u16,
    },
    Tui,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Server { port }) => {
            env_logger::init();
            info!("Running headless server on port {}...", port);
            // Server implementation remains here...
        }
        Some(Commands::Tui) | None => {
            run_tui(cli.interface).await?;
        }
    }
    Ok(())
}

async fn run_tui(interface: String) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load the eBPF bytecode
    let bytecode = include_bytes_aligned!("../../target/bpfel-unknown-none/release/vectura-ebpf");
    let mut bpf = Ebpf::load(bytecode)?;

    // 2. Attach to the Network Interface (TC hook)
    let _ = tc::qdisc_add_clsact(&interface);
    let program: &mut SchedClassifier = bpf.program_mut("vectura_ingress").unwrap().try_into()?;
    program.load()?;
    program.attach(&interface, TcAttachType::Ingress)?;

    // 3. Set up Kernel-to-User Communication (Using Synchronous PerfEventArray)
    let mut perf_array = PerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;
    let (tx, mut rx) = mpsc::channel::<PacketEvent>(1024);

    // Spawn blocking tasks to read from each CPU's perf buffer
    for cpu_id in online_cpus().map_err(|(_, err)| err)? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let tx = tx.clone();
        
        tokio::task::spawn_blocking(move || {
            loop {
                // Drain available events using the new functional API
                buf.for_each(|event| match event {
                    // Use .. to gracefully ignore the tail field
                    PerfEvent::Sample { head, .. } => {
                        // Ensure we have enough bytes to safely cast to our struct
                        if head.len() >= std::mem::size_of::<PacketEvent>() {
                            let ptr = head.as_ptr() as *const PacketEvent;
                            let event = unsafe { ptr.read_unaligned() };
                            // Bridge the data safely back to the async world
                            let _ = tx.blocking_send(event);
                        }
                    }
                    PerfEvent::Lost { count } => {
                        log::warn!("Ring buffer full! Lost {} events", count);
                    }
                });
                
                // Sleep slightly to prevent a CPU spin-loop since for_each is non-blocking
                std::thread::sleep(Duration::from_millis(10));
            }
        });


    }

    // 4. Initialize Ratatui Terminal
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut packet_history: VecDeque<PacketEvent> = VecDeque::with_capacity(20);
    let mut total_packets = 0;

    // 5. TUI Event Loop
    loop {
        while let Ok(event) = rx.try_recv() {
            total_packets += 1;
            packet_history.push_front(event);
            if packet_history.len() > 15 {
                packet_history.pop_back();
            }
        }

        // Draw the UI
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Length(3), Constraint::Min(10)].as_ref())
                .split(f.area());

            let header = Paragraph::new(format!(" Vectura Engine | Interface: {} | Total Packets: {}", interface, total_packets))
                .style(Style::default().fg(Color::Green))
                .block(Block::default().borders(Borders::ALL).title(" Status "));
            f.render_widget(header, chunks[0]);

            let rows: Vec<Row> = packet_history.iter().map(|e| {
                Row::new(vec![
                    Ipv4Addr::from(e.saddr).to_string(),
                    Ipv4Addr::from(e.daddr).to_string(),
                    e.protocol.to_string(),
                    format!("{} B", e.length),
                ])
            }).collect();

            let table = Table::new(
                rows,
                [Constraint::Percentage(30), Constraint::Percentage(30), Constraint::Percentage(20), Constraint::Percentage(20)]
            )
            .header(Row::new(vec!["Source IP", "Destination IP", "Protocol", "Size"]).style(Style::default().fg(Color::Yellow)))
            .block(Block::default().borders(Borders::ALL).title(" Live Traffic "));
            
            f.render_widget(table, chunks[1]);
        })?;

        // Handle Keyboard Input (Exit on 'q' or Esc)
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                    break;
                }
            }
        }
    }

    // Restore Terminal on exit
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}