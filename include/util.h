/**
 * @file    util.h
 * @brief   工具头文件：声明Link-RSUC方案中的常量和函数
 * @author  赵路路
 * @date    2025-02-16
 * @version 1.0
 *
 * 修改记录：
 * - 2025-02-16 赵路路：创建工程，编译测试
 * - 2025-02-17 赵路路：规范代码注释
 * - 2025-02-17 赵路路：更新系统初始化函数、hash函数、认证承诺生成函数
 */

#ifndef UTIL_H
#define UTIL_H

#include "types.h"

#define CLOCK_PRECISION 1E9

extern const char G_STR[];
extern const char P_STR[];
extern const char G_HAT_STR[];

extern mclBnG1 G, P;
extern mclBnG2 G_hat;

/**
 * @brief   测试用函数
 * @param   params  无
 * @return  无
 */
void util_function();

/**
 * @brief   hash函数，将群元素哈希到大整数
 * @param   params  哈希值 群元素 群元素个数
 * @return  无
 */
void hashElementsToBigInt(mclBnFr *out, const mclBnG1 *points, int num);

/**
 * @brief   系统初始化函数
 * @param   params  审计者私钥和公钥
 * @return  无
 */
void init_sys(ask_t ask, apk_t apk);

/**
 * @brief   集线器密钥生成函数
 * @param   params  集线器私钥和公钥
 * @return  无
 */
void keyGen(sk_t sk, vk_t vk);

/**
 * @brief   认证承诺生成函数
 * @param   params  承诺 签名 链接密文和标签 承诺值 集线器私钥 审计者公钥 随机数r 随机数k 证明proof
 * @return  无
 */
void authCom(commit_t cm, signature_t sigma, cp_t cp, mclBnFr *v, sk_t sk, apk_t apk, mclBnFr *r, mclBnFr *k, mclBnFr *r0, proof_t proof);

/**
 * @brief   承诺验证函数
 * @param   params  承诺 承诺值 随机数
 * @return  验证结果
 */
int vfCom(commit_t cm, mclBnFr *v, mclBnFr *r);

/**
 * @brief   签名验证函数
 * @param   params  承诺 链接密文和标签 签名 集线器公钥 审计者公钥 证明
 * @return  验证结果
 */
int vfAuth(commit_t cm, cp_t cp, signature_t sigma, vk_t vk, apk_t apk, proof_t proof);

/**
 * @brief   认证承诺随机化函数
 * @param   params  原承诺 原签名 随机化承诺 随机化签名 随机数
 * @return  无
 */
void rdmAC(commit_t cm_, signature_t sigma_, commit_t cm, signature_t sigma, mclBnFr *r_);

/**
 * @brief   认证承诺更新函数
 * @param   params  新承诺 新签名 原承诺 交易金额 集线器私钥
 * @return  无
 */
void updAC(commit_t cm_new, signature_t sigma_new, commit_t cm, mclBnFr *amt, sk_t sk);

/**
 * @brief   认证承诺更新验证函数
 * @param   params  原承诺 交易金额 新承诺 新签名 集线器公钥
 * @return  验证结果
 */
int vfUpd(commit_t cm, mclBnFr *amt, commit_t cm_new, signature_t sigma_new, vk_t vk);

/**
 * @brief   计时器函数
 * @param   params  无
 * @return  64位高精度时间，单位为纳秒
 */
int64_t ttimer();

#endif
