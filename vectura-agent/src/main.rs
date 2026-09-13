mod tui;
use maxminddb::{geoip2, Reader};
use aya::maps::RingBuf;
use std::os::fd::AsRawFd;
use tokio::io::unix::AsyncFd;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Bpf;
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
    pub geo_location: String,
    pub asn: String,
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
    pub bandwidth_history: Vec<u64>,
    pub last_tick: Instant,
    pub geo_reader: Option<Reader<&'static [u8]>>, 
    pub asn_reader: Option<Reader<&'static [u8]>>,
}

impl AppState {
    pub fn new() -> Self {
        let db_bytes = include_bytes!("../../GeoLite2-City.mmdb"); 
        
        let geo_reader = match Reader::from_source(db_bytes.as_slice()) {
            Ok(reader) => Some(reader),
            Err(e) => panic!("\n\n❌ Failed to parse the embedded GeoIP Database!\nError: {}\n\n", e),
        };

        let asn_bytes = include_bytes!("../../GeoLite2-ASN.mmdb"); 
        let asn_reader = match Reader::from_source(asn_bytes.as_slice()) {
            Ok(reader) => Some(reader),
            Err(e) => panic!("\n\n❌ Failed to parse the embedded ASN Database!\nError: {}\n\n", e),
        };

        Self {
            total_packets: 0,
            traffic_history: Vec::new(),
            ip_bytes: HashMap::new(),
            bytes_last_second: 0,
            current_mbps: 0.0,
            bandwidth_history: vec![0; 100],
            last_tick: Instant::now(),
            geo_reader,
            asn_reader,
        }
    }

    pub fn lookup_geo(&self, ip: Ipv4Addr) -> String {
        if ip.is_private() || ip.is_loopback() {
            return "LOCAL".to_string();
        }

        if let Some(reader) = &self.geo_reader {
            let ip_addr = std::net::IpAddr::V4(ip);
            
            if let Ok(result) = reader.lookup(ip_addr) {
                if let Ok(Some(city)) = result.decode::<geoip2::City>() {
                    if let Some(iso_code) = city.country.iso_code {
                        return iso_code.to_string(); 
                    }
                }
            }
        }
        "N/A".to_string()
    }

    pub fn lookup_asn(&self, ip: Ipv4Addr) -> String {
        if ip.is_private() || ip.is_loopback() {
            return "LOCAL".to_string();
        }

        if let Some(reader) = &self.asn_reader {
            let ip_addr = std::net::IpAddr::V4(ip);
            
            if let Ok(result) = reader.lookup(ip_addr) {
                if let Ok(Some(asn)) = result.decode::<geoip2::Asn>() {
                    let mut asn_str = String::new();
                    
                    if let Some(number) = asn.autonomous_system_number {
                        asn_str.push_str(&format!("AS{} ", number));
                    }
                    if let Some(org) = asn.autonomous_system_organization {
                        asn_str.push_str(org);
                    }
                    
                    if !asn_str.is_empty() {
                        if asn_str.len() > 35 {
                            asn_str.truncate(32);
                            asn_str.push_str("...");
                        }
                        return asn_str;
                    }
                }
            }
        }
        "N/A".to_string()
    }

    pub fn process_packet(&mut self, mut row: TrafficRow) {
        self.total_packets += 1;
        self.bytes_last_second += row.size as u64;

        let target_ip = if row.dst_ip.is_private() { row.src_ip } else { row.dst_ip };
        row.geo_location = self.lookup_geo(target_ip);
        row.asn = self.lookup_asn(target_ip);

        let flow_str = format!("{} ⟶ {}", row.src_ip, row.dst_ip);
        *self.ip_bytes.entry(flow_str).or_insert(0) += row.size as u64;

        self.traffic_history.push(row);
        if self.traffic_history.len() > 1000 {
            self.traffic_history.remove(0);
        }
    }

    pub fn on_tick(&mut self) {
        self.current_mbps = (self.bytes_last_second as f64 * 8.0) / 1_000_000.0;
        
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

    let mut ebpf = Bpf::load(aya::include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/vectura-ebpf"
    ))?;

    let _ = tc::qdisc_add_clsact(&args.interface);
    let program: &mut SchedClassifier = ebpf
        .program_mut("vectura_ingress")
        .unwrap()
        .try_into()?;
    program.load()?;
    
    program.attach(&args.interface, TcAttachType::Ingress)?;
    
    let egress_program: &mut SchedClassifier = ebpf
        .program_mut("vectura_egress")
        .unwrap()
        .try_into()?;
    egress_program.load()?;
    egress_program.attach(&args.interface, TcAttachType::Egress)?;

    let (tx, rx) = mpsc::channel::<TrafficRow>(1000);
    
    // RingBuf implementation replacing PerfEventArray
    let mut events = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;

    tokio::spawn(async move {
        let fd = events.as_raw_fd();
        let mut async_fd = AsyncFd::new(fd).expect("Failed to initialize AsyncFd");

        loop {
            let mut guard = async_fd.readable_mut().await.unwrap();

            while let Some(item) = events.next() {
                let raw_event = unsafe { 
                    std::ptr::read_unaligned(item.as_ptr() as *const PacketEvent) 
                };

                let row = TrafficRow {
                    timestamp: Local::now().format("%H:%M:%S.%3f").to_string(),
                    src_ip: Ipv4Addr::from(raw_event.src_ip),
                    dst_ip: Ipv4Addr::from(raw_event.dst_ip),
                    src_port: raw_event.src_port,
                    dst_port: raw_event.dst_port,
                    protocol: raw_event.protocol,
                    ttl: raw_event.ttl,
                    tcp_flags: raw_event.tcp_flags,
                    size: raw_event.size,
                    geo_location: String::new(),
                    asn: String::new(),
                };

                let _ = tx.send(row).await;
            }

            guard.clear_ready();
        }
    });

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal, rx, args.interface).await;

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
    let mut render_timer = interval(Duration::from_millis(33));

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