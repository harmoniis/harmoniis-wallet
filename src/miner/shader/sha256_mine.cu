// Simple SHA256 mining kernel — no intrinsics, standard C only.
extern "C" {

__device__ unsigned int rotr(unsigned int x, unsigned int n) {
    return (x >> n) | (x << (32u - n));
}
__device__ unsigned int ch(unsigned int x, unsigned int y, unsigned int z) {
    return (x & y) ^ (~x & z);
}
__device__ unsigned int maj(unsigned int x, unsigned int y, unsigned int z) {
    return (x & y) ^ (x & z) ^ (y & z);
}
__device__ unsigned int ep0(unsigned int x) { return rotr(x,2)^rotr(x,13)^rotr(x,22); }
__device__ unsigned int ep1(unsigned int x) { return rotr(x,6)^rotr(x,11)^rotr(x,25); }
__device__ unsigned int sig0(unsigned int x) { return rotr(x,7)^rotr(x,18)^(x>>3); }
__device__ unsigned int sig1(unsigned int x) { return rotr(x,17)^rotr(x,19)^(x>>10); }

__constant__ unsigned int K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

__global__ void mine_sha256(
    const unsigned int* nonce_table,
    unsigned int s0, unsigned int s1, unsigned int s2, unsigned int s3,
    unsigned int s4, unsigned int s5, unsigned int s6, unsigned int s7,
    unsigned int difficulty, unsigned int prefix_len,
    unsigned int nonce_offset, unsigned int nonce_count,
    unsigned long long* out_best
) {
    unsigned int gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= nonce_count) return;
    unsigned int nonce = nonce_offset + gid;
    unsigned int n1 = nonce / 1000u;
    unsigned int n2 = nonce % 1000u;
    unsigned int w0 = nonce_table[n1];
    unsigned int w1 = nonce_table[n2];
    // Build message schedule (only w0..w1 are nonce, rest is padding)
    unsigned int w[64];
    w[0] = w0; w[1] = w1;
    unsigned int total_bits = (prefix_len + 8u) * 8u;
    w[2] = 0x80000000u;
    for (int i = 3; i < 15; i++) w[i] = 0;
    w[15] = total_bits;
    for (int i = 16; i < 64; i++)
        w[i] = sig1(w[i-2]) + w[i-7] + sig0(w[i-15]) + w[i-16];
    unsigned int a=s0,b=s1,c=s2,d=s3,e=s4,f=s5,g=s6,h=s7;
    for (int i = 0; i < 64; i++) {
        unsigned int t1 = h + ep1(e) + ch(e,f,g) + K[i] + w[i];
        unsigned int t2 = ep0(a) + maj(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    unsigned int h0 = s0 + a;
    unsigned int zeros = __clz(h0);
    if (zeros >= difficulty) {
        unsigned long long packed = ((unsigned long long)zeros << 32) | (unsigned long long)nonce;
        atomicMax(out_best, packed);
    }
}

} // extern "C"
