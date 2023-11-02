#ifndef __AES_HASH_H__
#define __AES_HASH_H__

#include "util.h"
#include "gpu_vector.h"

class AesHash {
private:
  uint8_t *keyLeft_d = nullptr;
  uint8_t *keyRight_d = nullptr;
  void expand_encKey(uint8_t *encExpKey, uint8_t *key);
  void expand_decKey(uint8_t *decExpKey, uint8_t *key);

public:
  AesHash(uint8_t *newleft, uint8_t *newRight);
  virtual ~AesHash();
  virtual void expand_async(GPUvector<OTblock> &interleaved, GPUvector<OTblock> &separated,
	GPUvector<OTblock> &input, uint64_t width, cudaStream_t &s);
};

#endif
