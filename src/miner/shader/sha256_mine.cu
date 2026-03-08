// CUDA SHA256 mining kernel.
//
// Optimized output mode:
// - Midstate words are provided by host.
// - Each thread evaluates one nonce candidate.
// - Threads atomically reduce to one best packed u64:
//   upper 32 bits = leading-zero-bit count, lower 32 bits = nonce id.

extern "C" {

__device__ __forceinline__ unsigned int rotr(const unsigned int x, const unsigned int n) {
    return (x >> n) | (x << (32u - n));
}

__device__ __forceinline__ unsigned int ch(
    const unsigned int x,
    const unsigned int y,
    const unsigned int z
) {
    return (x & y) ^ (~x & z);
}

__device__ __forceinline__ unsigned int maj(
    const unsigned int x,
    const unsigned int y,
    const unsigned int z
) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ __forceinline__ unsigned int ep0(const unsigned int x) {
    return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u);
}

__device__ __forceinline__ unsigned int ep1(const unsigned int x) {
    return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u);
}

__device__ __forceinline__ unsigned int sig0(const unsigned int x) {
    return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u);
}

__device__ __forceinline__ unsigned int sig1(const unsigned int x) {
    return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u);
}

__constant__ unsigned int K[64] = {
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
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

__global__ void mine_sha256(
    const unsigned int* nonce_table,
    const unsigned int s0,
    const unsigned int s1,
    const unsigned int s2,
    const unsigned int s3,
    const unsigned int s4,
    const unsigned int s5,
    const unsigned int s6,
    const unsigned int s7,
    const unsigned int difficulty,
    const unsigned int prefix_len,
    const unsigned int nonce_offset,
    const unsigned int nonce_count,
    unsigned long long* out_best
) {
    const unsigned int local_id = blockIdx.x * blockDim.x + threadIdx.x;
    if (local_id >= nonce_count) {
        return;
    }

    const unsigned int thread_id = nonce_offset + local_id;
    if (thread_id >= 1000000u) {
        return;
    }

    const unsigned int nonce1_idx = thread_id / 1000u;
    const unsigned int nonce2_idx = thread_id % 1000u;

    // 16-word rolling message schedule.
    unsigned int w[16];
    w[0] = nonce_table[nonce1_idx];
    w[1] = nonce_table[nonce2_idx];
    w[2] = 0x66513d3du;  // "fQ=="
    w[3] = 0x80000000u;  // SHA256 padding bit
    w[4] = 0u;  w[5] = 0u;  w[6] = 0u;  w[7] = 0u;
    w[8] = 0u;  w[9] = 0u;  w[10] = 0u; w[11] = 0u;
    w[12] = 0u; w[13] = 0u;
    w[14] = 0u;
    w[15] = (prefix_len + 12u) * 8u;

    unsigned int a = s0;
    unsigned int b = s1;
    unsigned int c = s2;
    unsigned int d = s3;
    unsigned int e = s4;
    unsigned int f = s5;
    unsigned int g = s6;
    unsigned int h = s7;

    #pragma unroll
    for (unsigned int i = 0u; i < 64u; ++i) {
        unsigned int wi;
        if (i < 16u) {
            wi = w[i];
        } else {
            const unsigned int s0v = sig0(w[(i + 1u) & 15u]);
            const unsigned int s1v = sig1(w[(i + 14u) & 15u]);
            wi = w[i & 15u] = w[i & 15u] + s0v + s1v + w[(i + 9u) & 15u];
        }

        const unsigned int t1 = h + ep1(e) + ch(e, f, g) + K[i] + wi;
        const unsigned int t2 = ep0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    const unsigned int h0 = s0 + a;
    const unsigned int h1 = s1 + b;
    const unsigned int h2 = s2 + c;
    const unsigned int h3 = s3 + d;
    const unsigned int h4 = s4 + e;
    const unsigned int h5 = s5 + f;
    const unsigned int h6 = s6 + g;
    const unsigned int h7 = s7 + h;

    unsigned int zeros;
    if (h0 != 0u) {
        zeros = __clz(h0);
    } else {
        zeros = 32u;
        const unsigned int words[7] = {h1, h2, h3, h4, h5, h6, h7};
        #pragma unroll
        for (unsigned int i = 0u; i < 7u; ++i) {
            if (words[i] == 0u) {
                zeros += 32u;
            } else {
                zeros += __clz(words[i]);
                break;
            }
        }
    }

    if (zeros < difficulty) {
        return;
    }

    const unsigned long long packed =
        (static_cast<unsigned long long>(zeros) << 32) |
        static_cast<unsigned long long>(thread_id);
    atomicMax(out_best, packed);
}

} // extern "C"
