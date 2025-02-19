/**
 * @file    exp1.c
 * @brief   main函数：定义Link-RSUC方案中的执行流程
 * @author  赵路路
 * @date    2025-02-16
 * @version 1.0
 *
 * 修改记录：
 * - 2025-02-16 赵路路：创建工程，编译测试
 * - 2025-02-17 赵路路：规范代码注释，修改协议执行初始化函数、main函数
 * - 2025-02-18 赵路路：修改main函数
 */

#include <stdio.h>
#include "util.h"

ask_t ASK;
apk_t APK;
sk_t SK;
vk_t VK;
commit_t CM;
commit_t CM_;
commit_t CM_new;
cp_t CP;
cp_t CP_;
cp_t CP_new;
signature_t SIGMA;
signature_t SIGMA_;
signature_t SIGMA_new;
proof_t PROOF;
mclBnFr R, R_;
mclBnFr R0;
mclBnFr K, K_;
mclBnFr N;
mclBnFr V;
mclBnFr AMT;
mclBnFr RES;

/**
 * @brief   协议执行初始化函数
 * @param   params  无
 * @return  无
 */
void init_var()
{
    // 初始化审计者私钥
    ask_new(ASK);
    // 初始化审计者公钥
    apk_new(APK);
    // 初始化集线器私钥sk
    sk_new(SK);
    // 初始化集线器公钥vk
    vk_new(VK);
    // 初始化承诺CM, CM_, CM_new
    commit_new(CM);
    commit_new(CM_);
    commit_new(CM_new);
    // 初始化链接密文和标签CP, CP_, CP_new
    cp_new(CP);
    cp_new(CP_);
    cp_new(CP_new);
    // 初始化签名SIGMA, SIGMA_, SIGMA_new
    signature_new(SIGMA);
    signature_new(SIGMA_);
    signature_new(SIGMA_new);
    // 初始化证明PROOF
    proof_new(PROOF);
}

/**
 * @brief   main函数
 * @param   params  无
 * @return  执行结果
 */
int main()
{
    long long start_time, stop_time, total_time;

    // 系统初始化
    // printf("1. 系统初始化\n");
    start_time = ttimer();
    init_var();
    init_sys(ASK, APK);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("Setup time: %.5f sec\n\n", total_time / CLOCK_PRECISION);

    // 密钥生成
    // printf("2. 密钥生成\n");
    start_time = ttimer();
    keyGen(SK, VK);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("KeyGen time: %.5f sec\n\n", total_time / CLOCK_PRECISION);

    // 生成签名承诺
    // printf("3. 生成签名承诺\n");
    start_time = ttimer();
    int v_int = 3;
    mclBnFr_setInt(&V, v_int);
    authCom(CM, SIGMA, CP, &V, SK, APK, &R, &K, &R0, &N);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("AuthCom time: %.5f sec\n\n", total_time / CLOCK_PRECISION);

    // 打开承诺
    // printf("4. 打开承诺\n");
    start_time = ttimer();
    int res = vfCom(CM, &V, CP, APK, &R, &K, &R0, &N);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("VfCom time: %.5f sec\n\n", total_time / CLOCK_PRECISION);
    // printf("vfCom验证结果: %d\n\n", res);

    // 验证签名
    // printf("5. 验证签名\n");
    start_time = ttimer();
    res = vfAuth(CM, CP, SIGMA, VK, APK);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("VfAuth time: %.5f sec\n\n", total_time / CLOCK_PRECISION);
    // printf("vfAuth验证结果: %d\n\n", res);

    // 随机化签名承诺
    // printf("6. 随机化签名承诺\n");
    start_time = ttimer();
    rdmAC(CM_, SIGMA_, CP_, PROOF, APK, CM, SIGMA, CP, &R_, &K_, &K, &R0, &N);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("RdmAC time: %.5f sec\n\n", total_time / CLOCK_PRECISION);

    // 打开随机化后的承诺
    // printf("7. 打开随机化后的承诺\n");
    mclBnFr rr, kk, r0r, Nr;
    mclBnFr_add(&rr, &R, &R_);
    mclBnFr_add(&kk, &K, &K_);
    mclBnFr_add(&r0r, &R0, &R_);
    mclBnFr_add(&Nr, &N, &R_);
    res = vfCom(CM_, &V, CP_, APK, &rr, &kk, &r0r, &Nr);
    // printf("vfCom验证结果: %d\n\n", res);

    // 验证随机化后的签名
    // printf("8. 验证随机化后的签名\n");
    res = vfAuth(CM_, CP_, SIGMA_, VK, APK);
    // printf("vfAuth验证结果: %d\n\n", res);

    // 验证随机化后的证明
    // printf("9. 验证随机化后的证明\n");
    start_time = ttimer();
    res = vfProof(PROOF, CP_, APK);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("vfProof time: %.5f sec\n\n", total_time / CLOCK_PRECISION);
    // printf("vfProof验证结果: %d\n\n", res);

    // 更新签名承诺
    // printf("10. 更新签名承诺\n");
    start_time = ttimer();
    int amt_int = 3;
    mclBnFr_setInt(&AMT, amt_int);
    updAC(CM_new, SIGMA_new, CM_, CP_, &AMT, SK, APK);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("UpdAC time: %.5f sec\n\n", total_time / CLOCK_PRECISION);

    // 打开更新后的承诺
    // printf("11. 打开更新后的承诺\n");
    int res_int = v_int + amt_int;
    mclBnFr_setInt(&RES, res_int);
    res = vfCom(CM_new, &RES, CP_, APK, &rr, &kk, &r0r, &Nr);
    // printf("vfCom验证结果: %d\n\n", res);

    // 验证更新后的签名
    // printf("12. 验证更新后的签名\n");
    res = vfAuth(CM_new, CP_, SIGMA_new, VK, APK);
    // printf("vfAuth验证结果: %d\n\n", res);

    // 验证更新
    // printf("13. 验证更新\n");
    start_time = ttimer();
    res = vfUpd(CM_, &AMT, CP_, CM_new, SIGMA_new, VK, APK);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("VfUpd time: %.5f sec\n\n", total_time / CLOCK_PRECISION);
    // printf("vfUpd验证结果: %d\n\n", res);

    // 验证交易链接
    // printf("14. 验证交易链接\n");
    start_time = ttimer();
    res = linkCP(CP, CP_, PROOF, ASK, APK);
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("LinkCP time: %.5f sec\n\n", total_time / CLOCK_PRECISION);
    // printf("LinkCP验证结果: %d\n\n", res);

    return 0;
}
