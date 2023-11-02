#ifndef __GPU_MATMULT_H__
#define __GPU_MATMULT_H__

typedef struct {
    unsigned long long x, y;
} u128;

void gpu_init();
void gpu_launcher(u128 *r, int d, int n, u128 *nn, int k, const u128 *kk);

#endif
