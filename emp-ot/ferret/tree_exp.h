#ifndef __TREE_EXP_H__
#define __TREE_EXP_H__

void gpu_gmm_tree_gen(GPUvector<OTblock>& leftSum, GPUvector<OTblock>& rightSum,
    GPUvector<OTblock>& ggm_tree, GPUdata& secret, int depth);

#endif