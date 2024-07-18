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
mclBnFr AMT;
mclBnFr RES;

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
    long long start_time, stop_time, total_time;

    // 本次运行变量初始化+系统初始化+密钥生成
    // printf("1. 本次运行变量初始化+系统初始化+密钥生成\n\n");
    start_time = ttimer();
    init_var();
    init_sys();
    keyGen(SK, VK);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("Init time: %.5f sec\n\n", total_time / CLOCK_PRECISION);

    // 生成签名承诺
    // printf("2. 生成签名承诺\n\n");
    start_time = ttimer();
    int v_int = 3;
    mclBnFr_setInt(&V, v_int);
    authCom(CM, SIGMA, &V, SK, &R);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("AuthCom time: %.5f sec\n\n", total_time / CLOCK_PRECISION);

    // 打开承诺
    // printf("3. 打开承诺\n");
    start_time = ttimer();
    int res = vfCom(CM, &V, &R);
    // printf("vfCom验证结果: %d\n\n", res);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("VfCom time: %.5f sec\n\n", total_time / CLOCK_PRECISION);

    // 验证签名
    // printf("4. 验证签名\n");
    start_time = ttimer();
    res = vfAuth(CM, SIGMA, VK);
    // printf("vfAuth验证结果: %d\n\n", res);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("VfAuth time: %.5f sec\n\n", total_time / CLOCK_PRECISION);

    // 随机化签名承诺
    // printf("5. 随机化签名承诺\n\n");
    start_time = ttimer();
    rdmAC(CM_, SIGMA_, CM, SIGMA, &R_);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("RdmAC time: %.5f sec\n\n", total_time / CLOCK_PRECISION);

    // 打开随机化后的承诺
    // printf("6. 打开随机化后的承诺\n");
    mclBnFr rr;
    mclBnFr_add(&rr, &R, &R_);
    res = vfCom(CM_, &V, &rr);
    // printf("vfCom验证结果: %d\n\n", res);

    // 验证随机化后的签名
    // printf("7. 验证随机化后的签名\n");
    res = vfAuth(CM_, SIGMA_, VK);
    // printf("vfAuth验证结果: %d\n\n", res);

    // 更新签名承诺
    // printf("8. 更新签名承诺\n\n");
    start_time = ttimer();
    int amt_int = 3;
    mclBnFr_setInt(&AMT, amt_int);
    updAC(CM_new, SIGMA_new, CM_, &AMT, SK);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("UpdAC time: %.5f sec\n\n", total_time / CLOCK_PRECISION);

    // 打开更新后的承诺
    // printf("9. 打开更新后的承诺\n");
    int res_int = v_int + amt_int;
    mclBnFr_setInt(&RES, res_int);
    res = vfCom(CM_new, &RES, &rr);
    // printf("vfCom验证结果: %d\n\n", res);

    // 验证更新后的签名
    // printf("10. 验证更新后的签名\n");
    res = vfAuth(CM_new, SIGMA_new, VK);
    // printf("vfAuth验证结果: %d\n\n", res);

    // 验证更新
    // printf("11. 验证更新\n");
    start_time = ttimer();
    res = vfUpd(CM_, &AMT, CM_new, SIGMA_new, VK);
    // printf("vfUpd验证结果: %d\n\n", res);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("VfUpd time: %.5f sec\n\n", total_time / CLOCK_PRECISION);

    return 0;
}
