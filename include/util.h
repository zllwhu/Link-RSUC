#ifndef UTIL_H
#define UTIL_H

#include "types.h"

extern const char G_STR[];
extern const char P_STR[];
extern const char G_HAT_STR[];

extern sk_t sk;
extern vk_t vk;
extern mclBnG1 G, P;
extern mclBnG2 G_hat;
extern commit_t cm;
extern commit_t cm_;
extern commit_t cm_new;
extern signature_t sigma;
extern signature_t sigma_;
extern signature_t sigma_new;
extern mclBnFr r;
extern mclBnFr r_;
extern mclBnFr v;

void util_function();
void init();
void keyGen();
void authCom(mclBnFr *v, sk_t sk, mclBnFr *r);
int vfCom(commit_t cm, mclBnFr *v, mclBnFr *r);
int vfAuth(commit_t cm, signature_t sigma, vk_t vk);
void rdmAC(commit_t cm, signature_t sigma, mclBnFr *r_);

#endif
