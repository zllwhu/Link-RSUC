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