#ifndef UTIL_H
#define UTIL_H

#include "types.h"

extern const char G_STR[];
extern const char P_STR[];
extern const char G_HAT_STR[];

extern sk_t SK;
extern vk_t VK;
extern mclBnG1 G, P;
extern mclBnG2 G_hat;
extern commit_t CM;
extern commit_t CM_;
extern commit_t CM_new;
extern signature_t SIGMA;
extern signature_t SIGMA_;
extern signature_t SIGMA_new;
extern mclBnFr R;
extern mclBnFr R_;
extern mclBnFr V;

void util_function();
void init();
void keyGen();
void authCom(mclBnFr *v, sk_t sk, mclBnFr *r);
int vfCom(commit_t cm, mclBnFr *v, mclBnFr *r);
int vfAuth(commit_t cm, signature_t sigma, vk_t vk);
void rdmAC(commit_t cm, signature_t sigma, mclBnFr *r_);

#endif
