pub mod tui;

use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::{tc, SchedClassifier, TcAttachType},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{io, time::Duration};
use tokio::sync::mpsc;
use vectura_common::PacketEvent;
use tui::TrafficRow;

#[derive(Parser, Debug)]
#[command(name = "vectura", about = "Type & Memory Safe eBPF Network Analyzer")]
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
    let iface = cli.interface.clone();

    // 1. Load eBPF Bytecode
    let bytecode = include_bytes_aligned!("../../target/bpfel-unknown-none/release/vectura-ebpf");
    let mut bpf = Bpf::load(bytecode)?;

    // 2. Attach to Network Interface
    let _ = tc::qdisc_add_clsact(&iface);
    let program: &mut SchedClassifier = bpf.program_mut("vectura_ingress").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, TcAttachType::Ingress)?;

    // 3. Setup Terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 4. Spawn Background Tasks for ALL Online CPUs
    let (tx, mut rx) = mpsc::channel::<PacketEvent>(1000);
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let tx = tx.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10).map(|_| BytesMut::with_capacity(1024)).collect::<Vec<_>>();
            loop {
                if let Ok(events) = buf.read_events(&mut buffers).await {
                    for i in 0..events.read {
                        let buf_item = &mut buffers[i];
                        if buf_item.len() >= std::mem::size_of::<PacketEvent>() {
                            let event = unsafe { std::ptr::read_unaligned(buf_item.as_ptr() as *const PacketEvent) };
                            let _ = tx.send(event).await;
                        }
                    }
                }
            }
        });
    }

    let mut traffic_data: Vec<TrafficRow> = Vec::new();
    let mut total_packets = 0;

    // 5. Main TUI Event Loop
    loop {
        // Render UI FIRST on every frame
        terminal.draw(|f| tui::render_ui(f, &traffic_data, total_packets, &cli.interface))?;

// Non-blockingly drain all packets captured across all CPU cores
        while let Ok(event) = rx.try_recv() {
            // Keep a larger history buffer so we have enough data to fill large screens
            if traffic_data.len() >= 1000 {
                traffic_data.remove(0);
            }
            traffic_data.push(TrafficRow::from(event));
            total_packets += 1;
        }

        // Handle terminal key inputs without blocking screen updates
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                    break;
                }
            }
        }
    }

    // 6. Graceful Terminal Restore
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}