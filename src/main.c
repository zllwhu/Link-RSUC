#include <stdio.h>
#include "util.h"

int main()
{
    init();
    keyGen();
    int v_int = 3;
    mclBnFr_setInt(&V, v_int);
    authCom(&V, SK, &R);
    int res = vfCom(CM, &V, &R);
    printf("vfCom验证结果: %d\n", res);
    res = vfAuth(CM, SIGMA, VK);
    printf("vfAuth验证结果: %d\n", res);
    rdmAC(CM, SIGMA, &R_);
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
