/**
 * @file    exp2.c
 * @brief   main函数：定义Link-RSUC方案中的执行流程
 * @author  赵路路
 * @date    2025-02-19
 * @version 1.0
 *
 * 修改记录：
 * - 2025-02-19 赵路路：创建工程，编译测试
 */

 #include <stdio.h>
 #include "util.h"
 #include <secp256k1.h>
 
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
    long long start_time_s = 0, stop_time_s = 0, tmp_time_s = 0, total_time_s = 0;
    long long start_time_h = 0, stop_time_h = 0, tmp_time_h = 0, total_time_h = 0;
    long long start_time_r = 0, stop_time_r = 0, tmp_time_r = 0, total_time_r = 0;
    long long start_time_a = 0, stop_time_a = 0, tmp_time_a = 0, total_time_a = 0;

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char seckey[32] = {
        0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b,
        0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0xa3,
        0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0xa9, 0xba, 0xcb,
        0xdc, 0xed, 0xfe, 0x0f, 0x10, 0x21, 0x32, 0x43
    };
    secp256k1_pubkey pubkey;
    int a = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
    unsigned char msghash32[32] = {
        0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1,
        0xe2, 0xf3, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    };

    // Auditor执行Setup
    start_time_a = ttimer();
    init_var();
    init_sys(ASK, APK);
    stop_time_a = ttimer();
    tmp_time_a = stop_time_a - start_time_a;
    total_time_a += tmp_time_a;

    // Hub执行KeyGen、AuthCom
    start_time_h = ttimer();
    keyGen(SK, VK);
    int v_int = 3;
    mclBnFr_setInt(&V, v_int);
    authCom(CM, SIGMA, CP, &V, SK, APK, &R, &K, &R0, &N);
    stop_time_h = ttimer();
    tmp_time_h = stop_time_h - start_time_h;
    total_time_h += tmp_time_h;

    // Receiver执行VfCom、VfAuth、RdmAC
    start_time_r = ttimer();
    int res = vfCom(CM, &V, CP, APK, &R, &K, &R0, &N);
    res = vfAuth(CM, CP, SIGMA, VK, APK);
    rdmAC(CM_, SIGMA_, CP_, PROOF, APK, CM, SIGMA, CP, &R_, &K_, &K, &R0, &N);
    stop_time_r = ttimer();
    tmp_time_r = stop_time_r - start_time_r;
    total_time_r += tmp_time_r;

    // Sender执行VfAuth、VfProof、Sign
    start_time_s = ttimer();
    res = vfAuth(CM_, CP_, SIGMA_, VK, APK);
    res = vfProof(PROOF, CP_, APK);
    secp256k1_ecdsa_signature sig;
    res = secp256k1_ecdsa_sign(ctx, &sig, msghash32, seckey, NULL, NULL);
    unsigned char sig_serialized[64];
    res = secp256k1_ecdsa_signature_serialize_compact(ctx, sig_serialized, &sig);
    stop_time_s = ttimer();
    tmp_time_s = stop_time_s - start_time_s;
    total_time_s += tmp_time_s;

    // Hub执行Vf、VfAuth、VfProof、UpdAC
    start_time_h = ttimer();
    secp256k1_ecdsa_signature sig_deserialized;
    res = secp256k1_ecdsa_signature_parse_compact(ctx, &sig_deserialized, sig_serialized);
    res = secp256k1_ecdsa_verify(ctx, &sig_deserialized, msghash32, &pubkey);
    res = vfAuth(CM_, CP_, SIGMA_, VK, APK);
    res = vfProof(PROOF, CP_, APK);
    int amt_int = 3;
    mclBnFr_setInt(&AMT, amt_int);
    updAC(CM_new, SIGMA_new, CM_, CP_, &AMT, SK, APK);
    stop_time_h = ttimer();
    tmp_time_h = stop_time_h - start_time_h;
    total_time_h += tmp_time_h;

    // Sender执行VfUpd
    start_time_s = ttimer();
    res = vfAuth(CM_new, CP_, SIGMA_new, VK, APK);
    stop_time_s = ttimer();
    tmp_time_s = stop_time_s - start_time_s;
    total_time_s += tmp_time_s;

    // Receiver执行VfUpd、RdmAC
    start_time_r = ttimer();
    res = vfAuth(CM_new, CP_, SIGMA_new, VK, APK);
    rdmAC(CM_, SIGMA_, CP_, PROOF, APK, CM, SIGMA, CP, &R_, &K_, &K, &R0, &N);
    stop_time_r = ttimer();
    tmp_time_r = stop_time_r - start_time_r;
    total_time_r += tmp_time_r;

    printf("Sender time: %.5f sec\n\n", total_time_s / CLOCK_PRECISION);
    printf("Hub time: %.5f sec\n\n", total_time_h / CLOCK_PRECISION);
    printf("Receiver time: %.5f sec\n\n", total_time_r / CLOCK_PRECISION);
    printf("Auditor time: %.5f sec\n\n", total_time_a / CLOCK_PRECISION);

    secp256k1_context_destroy(ctx);
    return 0;
}
