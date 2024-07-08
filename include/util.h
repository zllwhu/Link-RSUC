#ifndef UTIL_H
#define UTIL_H

#include "types.h"

extern const char G_STR[];
extern const char P_STR[];
extern const char G_HAT_STR[];

extern mclBnG1 G, P;
extern mclBnG2 G_hat;

void util_function();
void init_sys();
void keyGen(sk_t sk, vk_t vk);
void authCom(commit_t cm, signature_t sigma, mclBnFr *v, sk_t sk, mclBnFr *r);
int vfCom(commit_t cm, mclBnFr *v, mclBnFr *r);
int vfAuth(commit_t cm, signature_t sigma, vk_t vk);
void rdmAC(commit_t cm_, signature_t sigma_, commit_t cm, signature_t sigma, mclBnFr *r_);

#endif
