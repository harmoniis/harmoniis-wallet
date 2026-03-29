// SHA256 mining compute shader.
//
// Each thread computes one SHA256 hash from a saved midstate + nonce pair,
// then checks if it meets the difficulty target (leading zero bits).
//
// Optimised output mode (matches CUDA kernel):
// - Midstate words are provided by host.
// - Each thread evaluates one nonce candidate.
// - Threads atomically reduce to one best packed result:
//   output[0] = best leading-zero count (via atomicMax)
//   output[1] = flat nonce id of the winner
//   output[2] = unused (reserved)
// - Host re-computes the actual hash from the winning nonce to verify.
//
// Layout:
//   binding 0: nonce_table — 1000 × u32 (base64-encoded 3-digit nonces, big-endian packed)
//   binding 1: input       — 12 × u32
//                            input[0..7]  = midstate[0..7]
//                            input[8]     = difficulty
//                            input[9]     = prefix_len
//                            input[10]    = nonce_offset
//                            input[11]    = nonce_count
//   binding 2: output      — 3 × u32 atomic (best_difficulty, nonce_id, reserved)

// SHA256 round constants
const K = array<u32, 64>(
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
);

@group(0) @binding(0) var<storage, read> nonce_table: array<u32, 1000>;
@group(0) @binding(1) var<storage, read> input: array<u32, 12>;  // midstate + params
@group(0) @binding(2) var<storage, read_write> output: array<atomic<u32>, 3>;

// SHA256 helper functions
fn rotr(x: u32, n: u32) -> u32 {
    return (x >> n) | (x << (32u - n));
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (~x & z);
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (x & z) ^ (y & z);
}

fn ep0(x: u32) -> u32 {
    return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u);
}

fn ep1(x: u32) -> u32 {
    return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u);
}

fn sig0(x: u32) -> u32 {
    return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u);
}

fn sig1(x: u32) -> u32 {
    return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u);
}

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let difficulty = input[8];
    let prefix_len = input[9];
    let nonce_offset = input[10];
    let nonce_count = input[11];

    if (gid.x >= nonce_count) {
        return;
    }

    let thread_id = nonce_offset + gid.x;
    if (thread_id >= 1000000u) {
        return;
    }

    let nonce1_idx = thread_id / 1000u;
    let nonce2_idx = thread_id % 1000u;

    // Load midstate
    let s0 = input[0]; let s1 = input[1]; let s2 = input[2]; let s3 = input[3];
    let s4 = input[4]; let s5 = input[5]; let s6 = input[6]; let s7 = input[7];

    // Rolling 16-word message schedule (matches CUDA — 4x less register pressure).
    //   word 0: nonce1, word 1: nonce2, word 2: "fQ==", word 3: 0x80 padding,
    //   words 4..14: zeros, word 15: bit-length.
    var w: array<u32, 16>;
    w[0] = nonce_table[nonce1_idx];
    w[1] = nonce_table[nonce2_idx];
    w[2] = 0x66513d3du;  // "fQ=="
    w[3] = 0x80000000u;  // padding
    w[4] = 0u; w[5] = 0u; w[6] = 0u; w[7] = 0u;
    w[8] = 0u; w[9] = 0u; w[10] = 0u; w[11] = 0u;
    w[12] = 0u; w[13] = 0u;
    w[14] = 0u;
    w[15] = (prefix_len + 12u) * 8u;

    // Compression rounds from midstate
    var a = s0; var b = s1; var c = s2; var d = s3;
    var e = s4; var f = s5; var g = s6; var h = s7;

    for (var i = 0u; i < 64u; i++) {
        var wi: u32;
        if (i < 16u) {
            wi = w[i];
        } else {
            let s0v = sig0(w[(i + 1u) & 15u]);
            let s1v = sig1(w[(i + 14u) & 15u]);
            wi = w[i & 15u] + s0v + s1v + w[(i + 9u) & 15u];
            w[i & 15u] = wi;
        }

        let t1 = h + ep1(e) + ch(e, f, g) + K[i] + wi;
        let t2 = ep0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    // Final hash = midstate + compression output
    let h0 = s0 + a;

    // Quick reject on first word (covers vast majority of candidates).
    if (h0 != 0u) {
        let lz = countLeadingZeros(h0);
        if (lz < difficulty) {
            return;
        }
        // difficulty <= 32 and first word has enough zeros.
        let prev = atomicMax(&output[0], lz);
        if (lz > prev) {
            atomicStore(&output[1], thread_id);
        }
        return;
    }

    // h0 == 0 -> at least 32 leading zero bits. Count further.
    let h1 = s1 + b;
    let h2 = s2 + c;
    let h3 = s3 + d;
    let h4 = s4 + e;
    let h5 = s5 + f;
    let h6 = s6 + g;
    let h7 = s7 + h;

    var zeros = 32u;
    let words = array<u32, 7>(h1, h2, h3, h4, h5, h6, h7);
    for (var i = 0u; i < 7u; i++) {
        if (words[i] == 0u) {
            zeros += 32u;
        } else {
            zeros += countLeadingZeros(words[i]);
            break;
        }
    }

    if (zeros >= difficulty) {
        let prev = atomicMax(&output[0], zeros);
        if (zeros > prev) {
            atomicStore(&output[1], thread_id);
        }
    }
}
