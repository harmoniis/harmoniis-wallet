// SHA-256 mining compute shader — FULLY UNROLLED.
//
// All 64 rounds manually expanded with:
// - Literal K constants (no dynamic array indexing)
// - Named w0-w15 variables (no array indexing overhead)
// - Inlined ep0/ep1/ch/maj/sig0/sig1 (no function call overhead)
// - Optimized maj: (a&b)|(c&(a|b)) — 2 ops instead of 3 XORs
// - Workgroup size 64 for better AMD RDNA occupancy
//
// Layout matches the non-unrolled version exactly.

@group(0) @binding(0) var<storage, read> nonce_table: array<u32, 1000>;
@group(0) @binding(1) var<storage, read> input: array<u32, 12>;
@group(0) @binding(2) var<storage, read_write> output: array<atomic<u32>, 3>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let difficulty = input[8];
    let nonce_offset = input[10];
    let nonce_count = input[11];

    if (gid.x >= nonce_count) { return; }

    let thread_id = nonce_offset + gid.x;
    if (thread_id >= 1000000u) { return; }

    let nonce1_idx = thread_id / 1000u;
    let nonce2_idx = thread_id % 1000u;

    // Load midstate
    let s0 = input[0]; let s1 = input[1]; let s2 = input[2]; let s3 = input[3];
    let s4 = input[4]; let s5 = input[5]; let s6 = input[6]; let s7 = input[7];

    // Message schedule: w0-w15 as named variables (no array indexing).
    var w0  = nonce_table[nonce1_idx];
    var w1  = nonce_table[nonce2_idx];
    var w2  = 0x66513d3du;
    var w3  = 0x80000000u;
    var w4  = 0u; var w5  = 0u; var w6  = 0u; var w7  = 0u;
    var w8  = 0u; var w9  = 0u; var w10 = 0u; var w11 = 0u;
    var w12 = 0u; var w13 = 0u; var w14 = 0u;
    var w15 = (input[9] + 12u) * 8u;

    var a = s0; var b = s1; var c = s2; var d = s3;
    var e = s4; var f = s5; var g = s6; var h = s7;

    // Round 0
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x428a2f98u + w0;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 1
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x71374491u + w1;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 2
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xb5c0fbcfu + w2;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 3
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xe9b5dba5u + w3;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 4
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x3956c25bu + w4;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 5
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x59f111f1u + w5;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 6
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x923f82a4u + w6;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 7
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xab1c5ed5u + w7;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 8
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xd807aa98u + w8;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 9
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x12835b01u + w9;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 10
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x243185beu + w10;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 11
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x550c7dc3u + w11;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 12
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x72be5d74u + w12;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 13
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x80deb1feu + w13;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 14
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x9bdc06a7u + w14;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 15
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xc19bf174u + w15;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 16
    w0 = w0 + (((w1 >> 7u) | (w1 << 25u)) ^ ((w1 >> 18u) | (w1 << 14u)) ^ (w1 >> 3u)) + (((w14 >> 17u) | (w14 << 15u)) ^ ((w14 >> 19u) | (w14 << 13u)) ^ (w14 >> 10u)) + w9;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xe49b69c1u + w0;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 17
    w1 = w1 + (((w2 >> 7u) | (w2 << 25u)) ^ ((w2 >> 18u) | (w2 << 14u)) ^ (w2 >> 3u)) + (((w15 >> 17u) | (w15 << 15u)) ^ ((w15 >> 19u) | (w15 << 13u)) ^ (w15 >> 10u)) + w10;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xefbe4786u + w1;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 18
    w2 = w2 + (((w3 >> 7u) | (w3 << 25u)) ^ ((w3 >> 18u) | (w3 << 14u)) ^ (w3 >> 3u)) + (((w0 >> 17u) | (w0 << 15u)) ^ ((w0 >> 19u) | (w0 << 13u)) ^ (w0 >> 10u)) + w11;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x0fc19dc6u + w2;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 19
    w3 = w3 + (((w4 >> 7u) | (w4 << 25u)) ^ ((w4 >> 18u) | (w4 << 14u)) ^ (w4 >> 3u)) + (((w1 >> 17u) | (w1 << 15u)) ^ ((w1 >> 19u) | (w1 << 13u)) ^ (w1 >> 10u)) + w12;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x240ca1ccu + w3;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 20
    w4 = w4 + (((w5 >> 7u) | (w5 << 25u)) ^ ((w5 >> 18u) | (w5 << 14u)) ^ (w5 >> 3u)) + (((w2 >> 17u) | (w2 << 15u)) ^ ((w2 >> 19u) | (w2 << 13u)) ^ (w2 >> 10u)) + w13;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x2de92c6fu + w4;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 21
    w5 = w5 + (((w6 >> 7u) | (w6 << 25u)) ^ ((w6 >> 18u) | (w6 << 14u)) ^ (w6 >> 3u)) + (((w3 >> 17u) | (w3 << 15u)) ^ ((w3 >> 19u) | (w3 << 13u)) ^ (w3 >> 10u)) + w14;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x4a7484aau + w5;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 22
    w6 = w6 + (((w7 >> 7u) | (w7 << 25u)) ^ ((w7 >> 18u) | (w7 << 14u)) ^ (w7 >> 3u)) + (((w4 >> 17u) | (w4 << 15u)) ^ ((w4 >> 19u) | (w4 << 13u)) ^ (w4 >> 10u)) + w15;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x5cb0a9dcu + w6;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 23
    w7 = w7 + (((w8 >> 7u) | (w8 << 25u)) ^ ((w8 >> 18u) | (w8 << 14u)) ^ (w8 >> 3u)) + (((w5 >> 17u) | (w5 << 15u)) ^ ((w5 >> 19u) | (w5 << 13u)) ^ (w5 >> 10u)) + w0;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x76f988dau + w7;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 24
    w8 = w8 + (((w9 >> 7u) | (w9 << 25u)) ^ ((w9 >> 18u) | (w9 << 14u)) ^ (w9 >> 3u)) + (((w6 >> 17u) | (w6 << 15u)) ^ ((w6 >> 19u) | (w6 << 13u)) ^ (w6 >> 10u)) + w1;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x983e5152u + w8;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 25
    w9 = w9 + (((w10 >> 7u) | (w10 << 25u)) ^ ((w10 >> 18u) | (w10 << 14u)) ^ (w10 >> 3u)) + (((w7 >> 17u) | (w7 << 15u)) ^ ((w7 >> 19u) | (w7 << 13u)) ^ (w7 >> 10u)) + w2;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xa831c66du + w9;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 26
    w10 = w10 + (((w11 >> 7u) | (w11 << 25u)) ^ ((w11 >> 18u) | (w11 << 14u)) ^ (w11 >> 3u)) + (((w8 >> 17u) | (w8 << 15u)) ^ ((w8 >> 19u) | (w8 << 13u)) ^ (w8 >> 10u)) + w3;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xb00327c8u + w10;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 27
    w11 = w11 + (((w12 >> 7u) | (w12 << 25u)) ^ ((w12 >> 18u) | (w12 << 14u)) ^ (w12 >> 3u)) + (((w9 >> 17u) | (w9 << 15u)) ^ ((w9 >> 19u) | (w9 << 13u)) ^ (w9 >> 10u)) + w4;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xbf597fc7u + w11;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 28
    w12 = w12 + (((w13 >> 7u) | (w13 << 25u)) ^ ((w13 >> 18u) | (w13 << 14u)) ^ (w13 >> 3u)) + (((w10 >> 17u) | (w10 << 15u)) ^ ((w10 >> 19u) | (w10 << 13u)) ^ (w10 >> 10u)) + w5;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xc6e00bf3u + w12;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 29
    w13 = w13 + (((w14 >> 7u) | (w14 << 25u)) ^ ((w14 >> 18u) | (w14 << 14u)) ^ (w14 >> 3u)) + (((w11 >> 17u) | (w11 << 15u)) ^ ((w11 >> 19u) | (w11 << 13u)) ^ (w11 >> 10u)) + w6;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xd5a79147u + w13;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 30
    w14 = w14 + (((w15 >> 7u) | (w15 << 25u)) ^ ((w15 >> 18u) | (w15 << 14u)) ^ (w15 >> 3u)) + (((w12 >> 17u) | (w12 << 15u)) ^ ((w12 >> 19u) | (w12 << 13u)) ^ (w12 >> 10u)) + w7;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x06ca6351u + w14;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 31
    w15 = w15 + (((w0 >> 7u) | (w0 << 25u)) ^ ((w0 >> 18u) | (w0 << 14u)) ^ (w0 >> 3u)) + (((w13 >> 17u) | (w13 << 15u)) ^ ((w13 >> 19u) | (w13 << 13u)) ^ (w13 >> 10u)) + w8;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x14292967u + w15;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 32
    w0 = w0 + (((w1 >> 7u) | (w1 << 25u)) ^ ((w1 >> 18u) | (w1 << 14u)) ^ (w1 >> 3u)) + (((w14 >> 17u) | (w14 << 15u)) ^ ((w14 >> 19u) | (w14 << 13u)) ^ (w14 >> 10u)) + w9;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x27b70a85u + w0;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 33
    w1 = w1 + (((w2 >> 7u) | (w2 << 25u)) ^ ((w2 >> 18u) | (w2 << 14u)) ^ (w2 >> 3u)) + (((w15 >> 17u) | (w15 << 15u)) ^ ((w15 >> 19u) | (w15 << 13u)) ^ (w15 >> 10u)) + w10;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x2e1b2138u + w1;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 34
    w2 = w2 + (((w3 >> 7u) | (w3 << 25u)) ^ ((w3 >> 18u) | (w3 << 14u)) ^ (w3 >> 3u)) + (((w0 >> 17u) | (w0 << 15u)) ^ ((w0 >> 19u) | (w0 << 13u)) ^ (w0 >> 10u)) + w11;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x4d2c6dfcu + w2;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 35
    w3 = w3 + (((w4 >> 7u) | (w4 << 25u)) ^ ((w4 >> 18u) | (w4 << 14u)) ^ (w4 >> 3u)) + (((w1 >> 17u) | (w1 << 15u)) ^ ((w1 >> 19u) | (w1 << 13u)) ^ (w1 >> 10u)) + w12;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x53380d13u + w3;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 36
    w4 = w4 + (((w5 >> 7u) | (w5 << 25u)) ^ ((w5 >> 18u) | (w5 << 14u)) ^ (w5 >> 3u)) + (((w2 >> 17u) | (w2 << 15u)) ^ ((w2 >> 19u) | (w2 << 13u)) ^ (w2 >> 10u)) + w13;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x650a7354u + w4;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 37
    w5 = w5 + (((w6 >> 7u) | (w6 << 25u)) ^ ((w6 >> 18u) | (w6 << 14u)) ^ (w6 >> 3u)) + (((w3 >> 17u) | (w3 << 15u)) ^ ((w3 >> 19u) | (w3 << 13u)) ^ (w3 >> 10u)) + w14;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x766a0abbu + w5;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 38
    w6 = w6 + (((w7 >> 7u) | (w7 << 25u)) ^ ((w7 >> 18u) | (w7 << 14u)) ^ (w7 >> 3u)) + (((w4 >> 17u) | (w4 << 15u)) ^ ((w4 >> 19u) | (w4 << 13u)) ^ (w4 >> 10u)) + w15;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x81c2c92eu + w6;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 39
    w7 = w7 + (((w8 >> 7u) | (w8 << 25u)) ^ ((w8 >> 18u) | (w8 << 14u)) ^ (w8 >> 3u)) + (((w5 >> 17u) | (w5 << 15u)) ^ ((w5 >> 19u) | (w5 << 13u)) ^ (w5 >> 10u)) + w0;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x92722c85u + w7;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 40
    w8 = w8 + (((w9 >> 7u) | (w9 << 25u)) ^ ((w9 >> 18u) | (w9 << 14u)) ^ (w9 >> 3u)) + (((w6 >> 17u) | (w6 << 15u)) ^ ((w6 >> 19u) | (w6 << 13u)) ^ (w6 >> 10u)) + w1;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xa2bfe8a1u + w8;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 41
    w9 = w9 + (((w10 >> 7u) | (w10 << 25u)) ^ ((w10 >> 18u) | (w10 << 14u)) ^ (w10 >> 3u)) + (((w7 >> 17u) | (w7 << 15u)) ^ ((w7 >> 19u) | (w7 << 13u)) ^ (w7 >> 10u)) + w2;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xa81a664bu + w9;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 42
    w10 = w10 + (((w11 >> 7u) | (w11 << 25u)) ^ ((w11 >> 18u) | (w11 << 14u)) ^ (w11 >> 3u)) + (((w8 >> 17u) | (w8 << 15u)) ^ ((w8 >> 19u) | (w8 << 13u)) ^ (w8 >> 10u)) + w3;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xc24b8b70u + w10;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 43
    w11 = w11 + (((w12 >> 7u) | (w12 << 25u)) ^ ((w12 >> 18u) | (w12 << 14u)) ^ (w12 >> 3u)) + (((w9 >> 17u) | (w9 << 15u)) ^ ((w9 >> 19u) | (w9 << 13u)) ^ (w9 >> 10u)) + w4;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xc76c51a3u + w11;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 44
    w12 = w12 + (((w13 >> 7u) | (w13 << 25u)) ^ ((w13 >> 18u) | (w13 << 14u)) ^ (w13 >> 3u)) + (((w10 >> 17u) | (w10 << 15u)) ^ ((w10 >> 19u) | (w10 << 13u)) ^ (w10 >> 10u)) + w5;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xd192e819u + w12;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 45
    w13 = w13 + (((w14 >> 7u) | (w14 << 25u)) ^ ((w14 >> 18u) | (w14 << 14u)) ^ (w14 >> 3u)) + (((w11 >> 17u) | (w11 << 15u)) ^ ((w11 >> 19u) | (w11 << 13u)) ^ (w11 >> 10u)) + w6;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xd6990624u + w13;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 46
    w14 = w14 + (((w15 >> 7u) | (w15 << 25u)) ^ ((w15 >> 18u) | (w15 << 14u)) ^ (w15 >> 3u)) + (((w12 >> 17u) | (w12 << 15u)) ^ ((w12 >> 19u) | (w12 << 13u)) ^ (w12 >> 10u)) + w7;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xf40e3585u + w14;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 47
    w15 = w15 + (((w0 >> 7u) | (w0 << 25u)) ^ ((w0 >> 18u) | (w0 << 14u)) ^ (w0 >> 3u)) + (((w13 >> 17u) | (w13 << 15u)) ^ ((w13 >> 19u) | (w13 << 13u)) ^ (w13 >> 10u)) + w8;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x106aa070u + w15;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 48
    w0 = w0 + (((w1 >> 7u) | (w1 << 25u)) ^ ((w1 >> 18u) | (w1 << 14u)) ^ (w1 >> 3u)) + (((w14 >> 17u) | (w14 << 15u)) ^ ((w14 >> 19u) | (w14 << 13u)) ^ (w14 >> 10u)) + w9;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x19a4c116u + w0;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 49
    w1 = w1 + (((w2 >> 7u) | (w2 << 25u)) ^ ((w2 >> 18u) | (w2 << 14u)) ^ (w2 >> 3u)) + (((w15 >> 17u) | (w15 << 15u)) ^ ((w15 >> 19u) | (w15 << 13u)) ^ (w15 >> 10u)) + w10;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x1e376c08u + w1;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 50
    w2 = w2 + (((w3 >> 7u) | (w3 << 25u)) ^ ((w3 >> 18u) | (w3 << 14u)) ^ (w3 >> 3u)) + (((w0 >> 17u) | (w0 << 15u)) ^ ((w0 >> 19u) | (w0 << 13u)) ^ (w0 >> 10u)) + w11;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x2748774cu + w2;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 51
    w3 = w3 + (((w4 >> 7u) | (w4 << 25u)) ^ ((w4 >> 18u) | (w4 << 14u)) ^ (w4 >> 3u)) + (((w1 >> 17u) | (w1 << 15u)) ^ ((w1 >> 19u) | (w1 << 13u)) ^ (w1 >> 10u)) + w12;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x34b0bcb5u + w3;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 52
    w4 = w4 + (((w5 >> 7u) | (w5 << 25u)) ^ ((w5 >> 18u) | (w5 << 14u)) ^ (w5 >> 3u)) + (((w2 >> 17u) | (w2 << 15u)) ^ ((w2 >> 19u) | (w2 << 13u)) ^ (w2 >> 10u)) + w13;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x391c0cb3u + w4;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 53
    w5 = w5 + (((w6 >> 7u) | (w6 << 25u)) ^ ((w6 >> 18u) | (w6 << 14u)) ^ (w6 >> 3u)) + (((w3 >> 17u) | (w3 << 15u)) ^ ((w3 >> 19u) | (w3 << 13u)) ^ (w3 >> 10u)) + w14;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x4ed8aa4au + w5;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 54
    w6 = w6 + (((w7 >> 7u) | (w7 << 25u)) ^ ((w7 >> 18u) | (w7 << 14u)) ^ (w7 >> 3u)) + (((w4 >> 17u) | (w4 << 15u)) ^ ((w4 >> 19u) | (w4 << 13u)) ^ (w4 >> 10u)) + w15;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x5b9cca4fu + w6;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 55
    w7 = w7 + (((w8 >> 7u) | (w8 << 25u)) ^ ((w8 >> 18u) | (w8 << 14u)) ^ (w8 >> 3u)) + (((w5 >> 17u) | (w5 << 15u)) ^ ((w5 >> 19u) | (w5 << 13u)) ^ (w5 >> 10u)) + w0;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x682e6ff3u + w7;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 56
    w8 = w8 + (((w9 >> 7u) | (w9 << 25u)) ^ ((w9 >> 18u) | (w9 << 14u)) ^ (w9 >> 3u)) + (((w6 >> 17u) | (w6 << 15u)) ^ ((w6 >> 19u) | (w6 << 13u)) ^ (w6 >> 10u)) + w1;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x748f82eeu + w8;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 57
    w9 = w9 + (((w10 >> 7u) | (w10 << 25u)) ^ ((w10 >> 18u) | (w10 << 14u)) ^ (w10 >> 3u)) + (((w7 >> 17u) | (w7 << 15u)) ^ ((w7 >> 19u) | (w7 << 13u)) ^ (w7 >> 10u)) + w2;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x78a5636fu + w9;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 58
    w10 = w10 + (((w11 >> 7u) | (w11 << 25u)) ^ ((w11 >> 18u) | (w11 << 14u)) ^ (w11 >> 3u)) + (((w8 >> 17u) | (w8 << 15u)) ^ ((w8 >> 19u) | (w8 << 13u)) ^ (w8 >> 10u)) + w3;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x84c87814u + w10;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 59
    w11 = w11 + (((w12 >> 7u) | (w12 << 25u)) ^ ((w12 >> 18u) | (w12 << 14u)) ^ (w12 >> 3u)) + (((w9 >> 17u) | (w9 << 15u)) ^ ((w9 >> 19u) | (w9 << 13u)) ^ (w9 >> 10u)) + w4;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x8cc70208u + w11;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 60
    w12 = w12 + (((w13 >> 7u) | (w13 << 25u)) ^ ((w13 >> 18u) | (w13 << 14u)) ^ (w13 >> 3u)) + (((w10 >> 17u) | (w10 << 15u)) ^ ((w10 >> 19u) | (w10 << 13u)) ^ (w10 >> 10u)) + w5;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0x90befffau + w12;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 61
    w13 = w13 + (((w14 >> 7u) | (w14 << 25u)) ^ ((w14 >> 18u) | (w14 << 14u)) ^ (w14 >> 3u)) + (((w11 >> 17u) | (w11 << 15u)) ^ ((w11 >> 19u) | (w11 << 13u)) ^ (w11 >> 10u)) + w6;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xa4506cebu + w13;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 62
    w14 = w14 + (((w15 >> 7u) | (w15 << 25u)) ^ ((w15 >> 18u) | (w15 << 14u)) ^ (w15 >> 3u)) + (((w12 >> 17u) | (w12 << 15u)) ^ ((w12 >> 19u) | (w12 << 13u)) ^ (w12 >> 10u)) + w7;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xbef9a3f7u + w14;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
    // Round 63
    w15 = w15 + (((w0 >> 7u) | (w0 << 25u)) ^ ((w0 >> 18u) | (w0 << 14u)) ^ (w0 >> 3u)) + (((w13 >> 17u) | (w13 << 15u)) ^ ((w13 >> 19u) | (w13 << 13u)) ^ (w13 >> 10u)) + w8;
    { let t1 = h + (((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u))) + ((e & f) ^ (~e & g)) + 0xc67178f2u + w15;
      let t2 = (((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u))) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }

    // Final hash = midstate + compression output
    let h0 = s0 + a;

    // Quick reject on first word
    if (h0 != 0u) {
        let lz = countLeadingZeros(h0);
        if (lz < difficulty) { return; }
        let prev = atomicMax(&output[0], lz);
        if (lz > prev) { atomicStore(&output[1], thread_id); }
        return;
    }

    // h0 == 0: count further
    var zeros = 32u;
    let tail = array<u32, 7>(s1+b, s2+c, s3+d, s4+e, s5+f, s6+g, s7+h);
    for (var i = 0u; i < 7u; i++) {
        if (tail[i] == 0u) { zeros += 32u; } else { zeros += countLeadingZeros(tail[i]); break; }
    }
    if (zeros >= difficulty) {
        let prev = atomicMax(&output[0], zeros);
        if (zeros > prev) { atomicStore(&output[1], thread_id); }
    }
}

