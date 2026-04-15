// Protocol Definition: Exported to main
// Rationale: We encapsulate the protocol definition to maintain a clean boundary between data structures and application logic.

use serde::{Serialize, Deserialize};

// Define a struct SPAPacket with the required fields
// Rationale: The packet must be compact to minimize transmission latency and fit within a single UDP datagram.
#[derive(Serialize, Deserialize, Debug)]
pub struct SPAPacket {
    // Identity ID of the client requesting access
    // Rationale: NIST 800-207 ZTA focuses on identity rather than network location.
    pub identity_id: u32,
    
    // Timestamp of the packet generation
    // Rationale: Prevent replay attacks by ensuring packets are processed within a valid time window.
    pub timestamp: u64,
    
    // HMAC-SHA256 signature
    // Rationale: Cryptographic proof of origin and integrity. Ensures the packet has not been tampered with.
    pub hmac_signature: [u8; 32],
}
