#include "emp-tool/emp-tool.h"
#include "emp-ot/ferret/gpu_matmult.h"
#include "emp-ot/ferret/aes_encrypt.cuh"

inline void CUDA_CALL(cudaError_t err) {
    if (err != cudaSuccess)
        printf("CUDA error: %s\n", cudaGetErrorString(err));
    assert(err == cudaSuccess);
}

__global__
void gpu_makeBlock(u128 *blocks) {
    uint64_t i = blockIdx.x * blockDim.x + threadIdx.x;
    uint64_t d = blockDim.y;
    uint64_t j = blockIdx.y * blockDim.y + threadIdx.y;
    blocks[d*i+j].x = 4*i;
    blocks[d*i+j].y = j;
}

__global__
void gpu_compute(uint32_t *r, int d, int k, u128 * nn, const u128 * kk) {
    uint64_t i = blockIdx.x * blockDim.x + threadIdx.x;
    u128 tmp = nn[i];
    for (int j = 0; j < d; ++j) {
        // decrease k such that fits in shared memory
        // increase t due to massive parallelisation
        // keep n constant based on required OTs
        u128 tmp = kk[r[d*i+j] % k];
        tmp.x ^= tmp.x;
        tmp.y ^= tmp.y;
    }
    nn[i] = tmp;
}

void gpu_init() {
    cudaFree(0);
}

void gpu_launcher(u128 *seed, int d, int n, u128 *nn, int k, const u128 *kk) {
    PRP prp(seed);

    u128 *r_in, *r_out, *nn_d, *kk_d;
    CUDA_CALL(cudaMalloc(&r_in, (d * n / 4) * sizeof(*r_in)));
    CUDA_CALL(cudaMalloc(&r_out, (d * n / 4) * sizeof(*r_out)));

    dim3 grid(n/4/1024, d);
    gpu_makeBlock<<<grid, 1024>>>(r_in);
    aesEncrypt128<<<d*n/4/1024, 1024>>>((uint32_t*)prp->aes.rd_key, r_out, r_in);

    CUDA_CALL(cudaMalloc(&nn_d, n * sizeof(*nn_d)));
    CUDA_CALL(cudaMalloc(&kk_d, k * sizeof(*kk_d)));
    CUDA_CALL(cudaMemcpy(nn_d, nn, n * sizeof(*nn_d), cudaMemcpyHostToDevice));
    CUDA_CALL(cudaMemcpy(kk_d, kk, k * sizeof(*kk_d), cudaMemcpyHostToDevice));

    gpu_compute<<<n / 1024, 1024>>>((uint32_t*)r_out, d, k, nn_d, kk_d);

    CUDA_CALL(cudaMemcpy(nn, nn_d, n * sizeof(*nn_d), cudaMemcpyDeviceToHost));
    CUDA_CALL(cudaDeviceSynchronize());
}

/*
void permute_block(block *data, int nblocks) {
    for(int i = 0; i < nblocks/AES_BATCH_SIZE; ++i) {
        AES_ecb_encrypt_blks<AES_BATCH_SIZE>(data + i*AES_BATCH_SIZE, &aes);
    }
    int remain = nblocks % AES_BATCH_SIZE;
    AES_ecb_encrypt_blks(data + nblocks - remain, remain, &aes);
}
*/
