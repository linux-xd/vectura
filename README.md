# 🚀 VECTURA: Next-Generation Network Observability

**A Type & Memory Safe eBPF Network Analyzer built purely in Rust. 🦀**

Vectura (from the Latin word for "transport" or "carriage") is a modern, high-performance network observability platform. By leveraging the [Aya eBPF framework](https://aya-rs.dev/), Vectura injects memory-safe Rust code directly into the Linux kernel to analyze network packets at wire speed. It bridges that raw data to a rich, asynchronous terminal UI (TUI) and a headless API in user-space.

---

## 💡 The Inspiration

For decades, network analysis forced engineers to make a difficult choice:

1. **Use user-space tools** (like `tcpdump` or Wireshark via libpcap), which incur massive CPU overhead due to constant context-switching and packet copying between kernel and user space.
2. **Write custom Kernel Modules in C**, which are incredibly fast but highly dangerous—a single memory leak or null pointer can cause a catastrophic kernel panic and take down the entire server.

Enter **eBPF (Extended Berkeley Packet Filter)**. eBPF revolutionized Linux by allowing sandboxed programs to run inside the kernel safely. However, the standard toolchains (BCC, libbpf) still required writing the kernel code in C, relying on massive LLVM/Clang toolchains at runtime.

Vectura was inspired by a simple question: *What if we could build an enterprise-grade network monitor where EVERY layer is memory-safe?*
Powered by the Aya framework, Vectura proves that Rust can dominate both user-space and kernel-space. It marries the raw, unbridled speed of kernel packet interception with the safety, concurrency (Tokio), and beautiful CLI ergonomics (Ratatui) that the Rust ecosystem is famous for.

---

## ✨ In-Depth Features

* 🛡️ **100% Rust Architecture:** Both the user-space agent and the kernel-space eBPF programs are written entirely in safe Rust. No C wrappers, no BCC dependencies, and no Clang required at runtime.
* ⚡ **Kernel-Level Speed via Traffic Control (TC):** Vectura attaches directly to the TC ingress hook. It reads IP headers the microsecond they hit the network interface, long before they traverse the complex Linux networking stack or reach standard applications.
* 🖥️ **Live Ratatui TUI Dashboard:** A hyper-responsive, real-time terminal interface that runs efficiently over SSH. It visualizes live packet feeds, source/destination IPs, and payload sizes without eating up your system resources.
* 🤖 **Headless Daemon & API:** Run Vectura as a background service. It embeds an asynchronous Axum REST server, allowing you to scrape kernel network metrics into Prometheus or Grafana for enterprise fleet monitoring.
* 🌉 **Zero-Copy IPC (PerfEventArray):** Kernel data isn't clumsily copied. Vectura uses high-speed, memory-mapped `PerfEventArray` ring buffers. Dedicated blocking threads in user-space poll this buffer and safely bridge the data into the Tokio async runtime.

---

## 🏗️ Platform Structure

Vectura is organized as a Cargo workspace to cleanly separate the compilation targets of the kernel and user-space binaries:

```text
vectura/
├── vectura-common/   📦 Shared data structs used by both Kernel & User
├── vectura-ebpf/     🧠 Kernel-Space Code (Compiles to eBPF bytecode)
├── vectura-agent/    💻 User-Space Code (Tokio Async, Ratatui, Axum Server)
└── xtask/            🛠️ Build automation scripts
```

---

## 🎯 Real-World Use Cases

* **SecOps & Intrusion Detection:** Audit live traffic and map internal subnet communication. Instantly identify anomalous payload sizes or unauthorized protocols hitting your servers.
* **DDoS & Flood Mitigation:** Monitor inbound packet velocity per source IP at the kernel level. Because it runs in TC, future updates to Vectura can actively drop malicious packets before they overwhelm the CPU.
* **Edge Computing Diagnostics:** A lightweight, dependency-free binary that can be deployed onto headless IoT devices or edge nodes for instantaneous, low-overhead network troubleshooting.

---

## 🛠️ Prerequisites

To build and run Vectura, you need a Linux system (Kernel 5.15+ recommended) and the Rust dual-toolchain setup.

**1. Install Rust Toolchains:**

```bash
rustup toolchain install stable
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
```

**2. Install the BPF Linker:**

```bash
cargo install bpf-linker
```

---

## 🚀 Compile & Build Guide

Because of the architectural separation, Vectura requires a two-step build:

**Step 1: Compile the Kernel eBPF Bytecode (Requires Nightly)**

```bash
cargo +nightly build --package vectura-ebpf --release --target bpfel-unknown-none -Z build-std=core,compiler_builtins
```

**Step 2: Compile the User-Space Agent (Requires Stable)**

```bash
cargo +stable build --package vectura-agent --release --target x86_64-unknown-linux-gnu
```

---

## 🕹️ Usage Instructions

*Note: Vectura requires `sudo` privileges to load eBPF bytecode into the Linux kernel and attach to network interfaces.*

### 1. Launching the Live TUI

Run the interactive dashboard on your target network interface (replace `wlan0` with your active interface, e.g., `eth0` or `enp3s0`).

```bash
sudo ./target/x86_64-unknown-linux-gnu/release/vectura-agent --interface wlan0 tui
```

🛑 **Controls:** Press `q` or `Esc` to safely detach the kernel hook and exit.

### 2. Launching the Headless Server

For continuous monitoring, run Vectura as a background server exposing a REST API.

```bash
sudo ./target/x86_64-unknown-linux-gnu/release/vectura-agent --interface wlan0 server --port 3000
```

📡 **Test the API:** `curl http://localhost:3000/metrics`

### 3. Manual Cleanup (Failsafe)

If the application exits abruptly (e.g., SIGKILL) and the eBPF hook fails to detach automatically, you can manually clear it using the `tc` command:

```bash
sudo tc qdisc del dev wlan0 clsact
```

---

## 🗺️ Development Roadmap

- [x] eBPF Ingress Hook Initialization
* [x] Synchronous `PerfEventArray` Kernel-to-User IPC
* [x] Live Ratatui Terminal Interface
* [ ] Deep Packet Inspection (TCP/UDP Port Extraction)
* [ ] SQLite Persistent Logging via SQLx
* [ ] Prometheus Metrics Exporter
* [ ] Implement `RingBuf` for kernel 5.8+ optimization

---

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

Please see our technical suggestions above in the Roadmap or check out the [Issues tab](../../issues) for `good first issue` tags (like IPv6 support or DNS resolution).

---
*Built with [Aya](https://aya-rs.dev/) — The future of eBPF is Rust. 🦀*
