// VM1 Generator (The Client)
// Rationale: Rust is chosen for the generator to ensure high-precision packet timing and minimal overhead during stress tests.

use clap::Parser;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::UdpSocket;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Import protocol module
// Rationale: Keeps protocol definitions modular.
mod protocol;
use protocol::SPAPacket;

// Define an alias for the HMAC-SHA256 type
// Rationale: Type alias for cleaner code when configuring HMAC.
type HmacSha256 = Hmac<Sha256>;

// Define CLI arguments using Clap
// Rationale: We need an easy way to pass dynamic parameters during automated benchmarking suites.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // Target IP address of the gatekeeper
    #[arg(short, long)]
    target: String,

    // Target UDP port of the gatekeeper
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    // Identity ID of the client
    #[arg(short, long)]
    identity: u32,

    // Shared secret for HMAC 
    // Rationale: Pre-shared key for authentication. In a full ZTA, this would be short-lived and dynamically rotated.
    #[arg(short, long)]
    secret: String,

    // Total packets to send
    #[arg(short, long, default_value_t = 1)]
    count: u32,

    // Target Packets Per Second (PPS). If 0, sprint max speed.
    #[arg(short, long, default_value_t = 1)]
    rate: u32,

    // Inter-packet delay in milliseconds (alternative to rate)
    #[arg(short = 'd', long)]
    delay: Option<u64>,
}

fn main() {
    // Parse CLI arguments
    let args = Args::parse();
    
    // Open a UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind socket");
    let target_addr = format!("{}:{}", args.target, args.port);

    // Determine interval
    let interval = if let Some(d) = args.delay {
        Some(Duration::from_millis(d))
    } else if args.rate > 0 {
        Some(Duration::from_micros(1_000_000 / args.rate as u64))
    } else {
        None // rate = 0 (max speed)
    };

    let start_time = Instant::now();
    let mut next_packet = Instant::now();
    if let Some(inv) = interval {
        next_packet += inv;
    }

    let mut packets_sent = 0;

    for _ in 0..args.count {
        // Get current time as timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        // Serialize identity and timestamp for HMAC computation
        let payload = bincode::serialize(&(args.identity, timestamp)).unwrap();

        // Initialize HMAC with the secret key
        let mut mac = HmacSha256::new_from_slice(args.secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(&payload);

        let result = mac.finalize();
        let signature_bytes = result.into_bytes();
        let mut hmac_signature = [0u8; 32];
        hmac_signature.copy_from_slice(&signature_bytes);

        // Construct the SPA packet
        let packet = SPAPacket {
            identity_id: args.identity,
            timestamp,
            hmac_signature,
        };

        // Serialize and send
        let serialized_packet = bincode::serialize(&packet).unwrap();
        socket.send_to(&serialized_packet, &target_addr).expect("Failed to send packet");
        packets_sent += 1;

        if let Some(inv) = interval {
            // Tunggu sampai target waktu tercapai (Busy-wait untuk presisi tinggi)
            while Instant::now() < next_packet {
                std::hint::spin_loop();
            }
            next_packet += inv;
        }
    }

    let elapsed = start_time.elapsed();
    let duration_ms = elapsed.as_millis();
    let actual_pps = if duration_ms > 0 {
        (packets_sent as u128 * 1000) / duration_ms
    } else {
        if packets_sent > 0 { packets_sent as u128 } else { 0 }
    };

    println!("Total packets sent: {}", packets_sent);
    println!("Total duration (ms): {}", duration_ms);
    println!("Actual average PPS: {}", actual_pps);
}
