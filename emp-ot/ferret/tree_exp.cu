#include "emp-ot/ferret/aes_expand.cuh"
#include "emp-tool/emp-tool.h"

#define AES_KEYSIZE 176

void gpu_ggm_tree_send(GPUvector<OTblock>& leftSum, GPUvector<OTblock>& rightSum,
    GPUvector<OTblock>& ggm_tree, GPUdata& secret_sum, const GPUdata& secret, int depth) {
    
    uint32_t k0_blk[4] = {3242342};
    uint32_t k1_blk[4] = {8993849};
    AesHash aesHash((uint8_t*) k0_blk, (uint8_t*) k1_blk);
    GPUvector<OTblock> separated(2 * numOT);

    for (uint64_t d = 1, w = 2; d <= depth; d++, w *= 2) {
        aesHash.expand(ggm_tree.data(w-1), separated, gmm_tree.data(w/2-1), w);
        separated.sum_async(2, w / 2);
        cudaMemcpy(leftSum.data(d-1), separated.data(0));
        cudaMemcpy(rightSum.data(d-1), separated.data(1));
    }

    // memset(secretSum, 0, sizeof(secretSum));
    // OTBlock one = { .data = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE} };
    // OTBlock *one_d;
    // cudaMalloc(&one_d, sizeof(*one_d));
    // cudaMemcpy(one_d, &one, sizeof(*one_d), cudaMemcpyHostToDevice);

    // ggm_tree.and_scalar(one_d);
    // GPUVector<OTBlock> nodes_sum(leave_n + 1);
    // nodes_sum = ggm_tree;
    // nodes_sum.set(leave_n, secret);
    // nodes_sum.sum(1, leave_n+1);
    // secret_sum = nodes_sum.data(0);
}

void gpu_ggm_tree_recv(GPUvector<OTblock>& ggm_tree, bool *choices,
    const GPUvector<OTblock>& sums, const GPUdata& secret_sum, uint64_t choice_pos) {
    
    uint32_t k0_blk[4] = {3242342};
    uint32_t k1_blk[4] = {8993849};
    AesHash aesHash((uint8_t*) k0_blk, (uint8_t*) k1_blk);
    GPUvector<OTblock> separated(2 * numOT);
    uint64_t activeParent = 0;
    uint8_t choice;
    uint64_t offset;

    for (uint64_t d = 1, w = 2; d <= depth; d++, w *= 2) {
        aesHash.expand(ggm_tree, separated, *inBuffer, w);
        choice = choices[d-1];
        offset = (w / 2) * choice + activeParent;
        cudaMemcpy(separated.data(offset), sums.data(d-1), sizeof(OTblock), cudaMemcpyDeviceToDevice);
        if (d == depth) {
            offset = (w / 2) * (1-choice) + activeParent;
            cudaMemcpy(separated.data(offset), sums.data(d), sizeof(OTblock), cudaMemcpyDeviceToDevice);
        }
        separated.sum_async(2, w / 2);
        offset = 2 * activeParent + choice;
        cudaMemcpy(outBuffer->data(offset), separated.data(choice), sizeof(OTblock), cudaMemcpyDeviceToDevice);
        if (d == depth) {
            offset = 2 * activeParent + (1-choice);
            cudaMemcpy(outBuffer->data(offset), separated.data(1-choice), sizeof(OTblock), cudaMemcpyDeviceToDevice);
        }

        activeParent *= 2;
        activeParent += 1 - choice;
    }

    // cudaMemset(ggm_tree.data(choice_pos), 0, sizeof(OTBlock));
    // OTBlock one = { .data = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE} };
    // OTBlock *one_d;
    // cudaMalloc(&one_d, sizeof(*one_d));
    // cudaMemcpy(one_d, &one, sizeof(*one_d), cudaMemcpyHostToDevice);

    // ggm_tree.and_scalar(one_d);
    // GPUVector<OTBlock> nodes_sum(leave_n + 1);
    // nodes_sum = ggm_tree;
    // nodes_sum.set(leave_n, secret_sum);
    // nodes_sum.sum(1, leave_n+1);
    // ggm_tree.set(choice_pos, nodes_sum.data(0));
}