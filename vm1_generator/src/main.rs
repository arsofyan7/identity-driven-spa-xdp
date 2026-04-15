// VM1 Generator (The Client)
// Rationale: Rust is chosen for the generator to ensure high-precision packet timing and minimal overhead during stress tests.

use clap::Parser;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};

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
}

fn main() {
    // Parse CLI arguments
    // Rationale: Extract execution parameters provided by the benchmarking scripts.
    let args = Args::parse();

    // Get current time as timestamp
    // Rationale: Timestamp is embedded in the packet payload to prevent replay attacks window.
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    // Serialize identity and timestamp for HMAC computation
    // Rationale: We only sign the payload data, not the signature field itself.
    let payload = bincode::serialize(&(args.identity, timestamp)).unwrap();

    // Initialize HMAC with the secret key
    // Rationale: Standard mechanism for authenticating message origin and integrity.
    let mut mac = HmacSha256::new_from_slice(args.secret.as_bytes())
        .expect("HMAC can take key of any size");
    
    // Update HMAC with the payload data
    // Rationale: This cryptographically binds the identity and timestamp together.
    mac.update(&payload);

    // Finalize the signature and extract bytes
    // Rationale: Convert the result into the fixed-size 32-byte array needed by the SPAPacket struct.
    let result = mac.finalize();
    let signature_bytes = result.into_bytes();
    let mut hmac_signature = [0u8; 32];
    hmac_signature.copy_from_slice(&signature_bytes);

    // Construct the SPA packet
    // Rationale: Creating the structured object before serialization ensures fields match exactly.
    let packet = SPAPacket {
        identity_id: args.identity,
        timestamp,
        hmac_signature,
    };

    // Serialize the full packet
    // Rationale: Convert the struct into a binary format suitable for UDP transmission. bincode is chosen for minimal overhead.
    let serialized_packet = bincode::serialize(&packet).unwrap();

    // Open a UDP socket
    // Rationale: UDP is used for SPA packets because it does not require an established connection (like TCP), enhancing stealth.
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind socket");

    // Send the serialized packet to the target gatekeeper
    // Rationale: Fire-and-forget mechanism is critical for stealth. The port is typically closed/stealthy on the receiver via firewall.
    let target_addr = format!("{}:{}", args.target, args.port);
    socket.send_to(&serialized_packet, target_addr).expect("Failed to send packet");

    // Output confirmation
    // Rationale: Useful for verification during Phase 0 baseline testing.
    println!("Sent SPA packet to {} for ID {} at TS {}", args.target, args.identity, timestamp);
}
