mod tui;

use aya::maps::AsyncPerfEventArray;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::util::online_cpus;
use aya::Bpf;
use bytes::BytesMut;
use chrono::Local;
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::interval;
use vectura_common::{
    PacketEvent, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN, TCP_FLAG_URG,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "wlp4s0")]
    interface: String,
}

#[derive(Clone, Debug)]
pub struct TrafficRow {
    pub timestamp: String,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub ttl: u8,
    pub tcp_flags: u8,
    pub size: u32,
}

impl TrafficRow {
    pub fn protocol_name(&self) -> String {
        match self.protocol {
            1 => "ICMP".to_string(),
            6 => {
                let flags = self.format_flags();
                if flags.is_empty() {
                    "TCP".to_string()
                } else {
                    format!("TCP [{}]", flags)
                }
            }
            17 => {
                if self.src_port == 53 || self.dst_port == 53 {
                    "DNS (UDP)".to_string()
                } else {
                    "UDP".to_string()
                }
            }
            _ => format!("IP ({})", self.protocol),
        }
    }

    pub fn format_flags(&self) -> String {
        let mut f = String::new();
        if self.tcp_flags & TCP_FLAG_SYN != 0 { f.push_str("SYN "); }
        if self.tcp_flags & TCP_FLAG_ACK != 0 { f.push_str("ACK "); }
        if self.tcp_flags & TCP_FLAG_FIN != 0 { f.push_str("FIN "); }
        if self.tcp_flags & TCP_FLAG_RST != 0 { f.push_str("RST "); }
        if self.tcp_flags & TCP_FLAG_PSH != 0 { f.push_str("PSH "); }
        if self.tcp_flags & TCP_FLAG_URG != 0 { f.push_str("URG "); }
        f.trim_end().to_string()
    }

    pub fn remote_target(&self) -> String {
        if self.dst_ip.is_private() || self.dst_ip.is_loopback() {
            self.src_ip.to_string()
        } else {
            self.dst_ip.to_string()
        }
    }

    pub fn direction_symbol(&self) -> &'static str {
        // If the destination IP is your local machine/network, it is inbound reverse traffic
        if self.dst_ip.is_private() || self.dst_ip.is_loopback() {
            "<--"
        } else {
            "-->"
        }
    }
}

pub struct AppState {
    pub total_packets: u64,
    pub traffic_history: Vec<TrafficRow>,
    pub ip_bytes: HashMap<String, u64>,
    pub bytes_last_second: u64,
    pub current_mbps: f64,
    pub bandwidth_history: Vec<u64>, // NEW: Track graph data points
    pub last_tick: Instant,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            total_packets: 0,
            traffic_history: Vec::new(),
            ip_bytes: HashMap::new(),
            bytes_last_second: 0,
            current_mbps: 0.0,
            bandwidth_history: vec![0; 100], // NEW: Pre-fill with 100 seconds of zeros
            last_tick: Instant::now(),
        }
    }

pub fn process_packet(&mut self, row: TrafficRow) {
        self.total_packets += 1;
        self.bytes_last_second += row.size as u64;

        // Change this to track the full flow from Source to Destination!
        let flow_str = format!("{} ⟶ {}", row.src_ip, row.dst_ip);
        *self.ip_bytes.entry(flow_str).or_insert(0) += row.size as u64;

        self.traffic_history.push(row);
        if self.traffic_history.len() > 1000 {
            self.traffic_history.remove(0);
        }
    }

    pub fn on_tick(&mut self) {
        self.current_mbps = (self.bytes_last_second as f64 * 8.0) / 1_000_000.0;
        
        // NEW: Push the raw bytes into our history graph and trim it
        self.bandwidth_history.push(self.bytes_last_second);
        if self.bandwidth_history.len() > 100 {
            self.bandwidth_history.remove(0);
        }
        
        self.bytes_last_second = 0;
        self.last_tick = Instant::now();
    }

    pub fn top_talkers(&self) -> Vec<(String, u64)> {
        let mut talkers: Vec<_> = self.ip_bytes.iter().map(|(k, v)| (k.clone(), *v)).collect();
        talkers.sort_by(|a, b| b.1.cmp(&a.1));
        talkers.into_iter().take(5).collect()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // 1. Load embedded BPF program
let mut ebpf = Bpf::load(aya::include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/vectura-ebpf"
    ))?;

    // 2. Attach Traffic Control (TC) ingress hook
let _ = tc::qdisc_add_clsact(&args.interface);
    let program: &mut SchedClassifier = ebpf
        .program_mut("vectura_ingress")
        .unwrap()
        .try_into()?;
    program.load()?;
    
    // Catch incoming traffic
    program.attach(&args.interface, TcAttachType::Ingress)?;
    
    // Catch outgoing traffic (This is the missing piece!)
    program.attach(&args.interface, TcAttachType::Egress)?;

    // 3. Multi-core eBPF async polling setup
    let (tx, rx) = mpsc::channel::<TrafficRow>(1000);
    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let tx = tx.clone();

        tokio::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(1024); 10];
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &buffers[i];
                    let ptr = buf.as_ptr() as *const PacketEvent;
                    let event = unsafe { *ptr };

                    let row = TrafficRow {
                        timestamp: Local::now().format("%H:%M:%S.%3f").to_string(),
                        src_ip: Ipv4Addr::from(event.src_ip),
                        dst_ip: Ipv4Addr::from(event.dst_ip),
                        src_port: event.src_port,
                        dst_port: event.dst_port,
                        protocol: event.protocol,
                        ttl: event.ttl,
                        tcp_flags: event.tcp_flags,
                        size: event.size,
                    };

                    let _ = tx.send(row).await;
                }
            }
        });
    }

    // 4. Initialize Terminal
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 5. Run Application Event Loop
    let res = run_app(&mut terminal, rx, args.interface).await;

    // 6. Terminal Cleanup on Exit
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("Error: {:?}", err);
    }

    Ok(())
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    mut rx: mpsc::Receiver<TrafficRow>,
    interface: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = AppState::new();
    let mut bandwidth_timer = interval(Duration::from_secs(1));
    let mut render_timer = interval(Duration::from_millis(33)); // ~30 FPS

    loop {
        tokio::select! {
            Some(row) = rx.recv() => {
                state.process_packet(row);
            }

            _ = bandwidth_timer.tick() => {
                state.on_tick();
            }

            _ = render_timer.tick() => {
                terminal.draw(|f| tui::render_ui(f, &state, &interface))?;

                if event::poll(Duration::from_millis(0))? {
                    if let Event::Key(key) = event::read()? {
                        if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}