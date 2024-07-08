#include <stdio.h>
#include "util.h"

sk_t SK;
vk_t VK;
commit_t CM;
commit_t CM_;
commit_t CM_new;
signature_t SIGMA;
signature_t SIGMA_;
signature_t SIGMA_new;
mclBnFr R;
mclBnFr R_;
mclBnFr V;

void init_var()
{
    // 初始化私钥sk
    sk_new(SK);
    // 初始化公钥vk
    vk_new(VK);
    // 初始化承诺CM, CM_, CM_new
    commit_new(CM);
    commit_new(CM_);
    commit_new(CM_new);
    // 初始化签名SIGMA, SIGMA_, SIGMA_new
    signature_new(SIGMA);
    signature_new(SIGMA_);
    signature_new(SIGMA_new);
}

int main()
{
    init_var();
    init_sys();
    keyGen(SK, VK);
    int v_int = 3;
    mclBnFr_setInt(&V, v_int);
    authCom(CM, SIGMA, &V, SK, &R);
    int res = vfCom(CM, &V, &R);
    printf("vfCom验证结果: %d\n", res);
    res = vfAuth(CM, SIGMA, VK);
    printf("vfAuth验证结果: %d\n", res);
    rdmAC(CM_, SIGMA_, CM, SIGMA, &R_);
    mclBnFr rr;
    mclBnFr_add(&rr, &R, &R_);
    res = vfCom(CM_, &V, &rr);
    printf("vfCom验证结果: %d\n", res);
    res = vfAuth(CM_, SIGMA_, VK);
    printf("vfAuth验证结果: %d\n", res);

    // char cm_c0[1000];
    // char cm_c1[1000];
    // char sigma_z[1000];
    // char sigma_s[1000];
    // char sigma_s_hat[1000];
    // char sigma_t[1000];
    // mclBnG1_getStr(cm_c0, 1000, &cm->c0, 16);
    // mclBnG1_getStr(cm_c1, 1000, &cm->c1, 16);
    // mclBnG1_getStr(sigma_z, 1000, &sigma->z, 16);
    // mclBnG1_getStr(sigma_s, 1000, &sigma->s, 16);
    // mclBnG2_getStr(sigma_s_hat, 1000, &sigma->s_hat, 16);
    // mclBnG1_getStr(sigma_t, 1000, &sigma->t, 16);
    // printf("%s\n%s\n%s\n%s\n%s\n%s\n", cm_c0, cm_c1, sigma_z, sigma_s, sigma_s_hat, sigma_t);

    return 0;
}
