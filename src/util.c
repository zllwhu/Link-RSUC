/**
 * @file    util.c
 * @brief   工具函数：定义Link-RSUC方案中的常量和函数
 * @author  赵路路
 * @date    2025-02-16
 * @version 1.0
 *
 * 修改记录：
 * - 2025-02-16 赵路路：创建工程，编译测试
 * - 2025-02-17 赵路路：规范代码注释，修改系统初始化函数、认证承诺生成函数、承诺验证函数、签名验证函数，新增hash函数、证明验证函数
 * - 2025-02-18 赵路路：修改承诺验证函数、认证承诺随机化函数、认证承诺更新函数、认证承诺更新验证函数，新增链接交易函数
 */

#include <string.h>
#include <stdio.h>
#include <mcl/bn_c256.h>
#include <tomcrypt.h>
#include <time.h>
#include "util.h"

const char G_STR[] = "1 1 2";
const char P_STR[] = "1 1368015179489954701390400359078579693043519447331113978918064868415326638035 9918110051302171585080402603319702774565515993150576347155970296011118125764";
const char G_HAT_STR[] = "1 10857046999023057135944570762232829481370756359578518086990519993285655852781 11559732032986387107991004021392285783925812861821192530917403151452391805634 8495653923123431417604973247489272438418190587263600148770280649306958101930 4082367875863433681332203403145435568316851327593401208105741076214120093531";

mclBnG1 G, P;
mclBnG2 G_hat;

/**
 * @brief   测试用函数
 * @param   params  无
 * @return  无
 */
void util_function()
{
    printf("Util function called.\n");
}

/**
 * @brief   计时器函数
 * @param   params  无
 * @return  64位高精度时间，单位为纳秒
 */
int64_t ttimer()
{
    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return (int64_t)time.tv_sec * CLOCK_PRECISION + time.tv_nsec;
}

/**
 * @brief   hash函数，将群元素哈希到大整数
 * @param   params  哈希值 群元素 群元素个数
 * @return  无
 */
void hashElementsToBigInt(mclBnFr *out, const mclBnG1 *points, int num) {
    // sha256算法初始化
    unsigned char hash[32];
    hash_state md;
    sha256_init(&md);

    // 遍历所有群元素，进行序列化
    for (int i = 0; i < num; i++) {
        // G1群元素包含3个Fr，占用96字节
        unsigned char buf[128];
        size_t bufSize = mclBnG1_serialize(buf, sizeof(buf), &points[i]);
        if (bufSize == 0) {
            fprintf(stderr, "G1序列化失败\n");
            exit(1);
        }
        sha256_process(&md, buf, bufSize);
    }

    // 计算最终的哈希值
    sha256_done(&md, hash);

    // 将哈希值转换为mclBnFr
    if (mclBnFr_setBigEndianMod(out, hash, sizeof(hash)) != 0) {
        fprintf(stderr, "哈希到大整数失败\n");
        exit(1);
    }
}

/**
 * @brief   系统初始化函数
 * @param   params  审计者私钥和公钥
 * @return  无
 */
void init_sys(ask_t ask, apk_t apk)
{
    // 初始化mcl使用的曲线
    mclBn_init(MCL_BN_SNARK1, MCLBN_COMPILED_TIME_VAR);
    // 初始化生成元G, P, G_hat
    mclBnG1_setStr(&G, G_STR, strlen(G_STR), 10);
    mclBnG1_setStr(&P, P_STR, strlen(P_STR), 10);
    mclBnG2_setStr(&G_hat, G_HAT_STR, strlen(G_HAT_STR), 10);

    // 选取审计者私钥ask
    mclBnFr_setByCSPRNG(&ask->x);
    // 计算审计者公钥apk
    mclBnG1_mul(&apk->x, &G, &ask->x);
}

/**
 * @brief   集线器密钥生成函数
 * @param   params  私钥和公钥
 * @return  无
 */
void keyGen(sk_t sk, vk_t vk)
{
    // 选取私钥sk
    mclBnFr_setByCSPRNG(&sk->x0);
    mclBnFr_setByCSPRNG(&sk->x1);
    // 计算公钥vk
    mclBnG2_mul(&vk->x0_hat, &G_hat, &sk->x0);
    mclBnG2_mul(&vk->x1_hat, &G_hat, &sk->x1);
}

/**
 * @brief   认证承诺生成函数
 * @param   params  承诺 签名 链接密文和标签 承诺值 集线器私钥 审计者公钥 随机数r 随机数k 随机数r0 随机数N
 * @return  无
 */
void authCom(commit_t cm, signature_t sigma, cp_t cp, mclBnFr *v, sk_t sk, apk_t apk, mclBnFr *r, mclBnFr *k, mclBnFr *r0, mclBnFr *N)
{
    // 随机数
    mclBnFr s, s_inv;
    // 承诺和密文中间量
    mclBnG1 vg, rp, r0g, kapk;
    // 签名中间量
    mclBnG1 z, x0c0, x1c1, x0cp0, x1cp1, z1, z2, z3;
    mclBnG1 t, u, x0g, x1p, x1apk, x1g;

    // 随机选取k, r0计算链接密文cp
    mclBnFr_setByCSPRNG(k);
    mclBnFr_setByCSPRNG(r0);
    // 计算链接密文cp
    mclBnG1_mul(&cp->cp0, &G, k);
    mclBnG1_mul(&r0g, &G, r0);
    mclBnG1_mul(&kapk, &apk->x, k);
    mclBnG1_add(&cp->cp1, &r0g, &kapk);

    // 随机选取N计算链接标签tag
    mclBnFr_setByCSPRNG(N);
    // 计算链接标签tag
    mclBnG1_mul(&cp->tag, &G, N);

    // 随机选取r计算承诺cm
    mclBnFr_setByCSPRNG(r);
    // 计算承诺cm
    mclBnG1_mul(&cm->c0, &G, r);
    mclBnG1_mul(&vg, &G, v);
    mclBnG1_mul(&rp, &P, r);
    mclBnG1_add(&cm->c1, &vg, &rp);

    // 随机选取s计算签名sigma
    mclBnFr_setByCSPRNG(&s);
    mclBnFr_inv(&s_inv, &s);
    // 计算签名sigma中的z
    mclBnG1_mul(&x0c0, &cm->c0, &sk->x0);
    mclBnG1_mul(&x1c1, &cm->c1, &sk->x1);
    mclBnG1_mul(&x0cp0, &cp->cp0, &sk->x0);
    mclBnG1_mul(&x1cp1, &cp->cp1, &sk->x1);
    mclBnG1_add(&z1, &x0c0, &x1c1);
    mclBnG1_add(&z2, &x0cp0, &x1cp1);
    mclBnG1_add(&z3, &z1, &z2);
    mclBnG1_add(&z, &z3, &G);
    mclBnG1_mul(&sigma->z, &z, &s_inv);
    // 计算签名sigma中的s
    mclBnG1_mul(&sigma->s, &G, &s);
    // 计算签名sigma中的s_hat
    mclBnG2_mul(&sigma->s_hat, &G_hat, &s);
    // 计算签名sigma中的t
    mclBnG1_mul(&x0g, &G, &sk->x0);
    mclBnG1_mul(&x1p, &P, &sk->x1);
    mclBnG1_add(&t, &x0g, &x1p);
    mclBnG1_mul(&sigma->t, &t, &s_inv);
    // 计算签名sigma中的u
    mclBnG1_mul(&x1apk, &apk->x, &sk->x1);
    mclBnG1_add(&u, &x0g, &x1apk);
    mclBnG1_mul(&sigma->u, &u, &s_inv);
    // 计算签名sigma中的v
    mclBnG1_mul(&x1g, &G, &sk->x1);
    mclBnG1_mul(&sigma->v, &x1g, &s_inv);
}

/**
 * @brief   承诺验证函数
 * @param   params  承诺 承诺值 链接密文和标签 审计者公钥 随机数r 随机数k 随机数r0 随机数N
 * @return  验证结果
 */
int vfCom(commit_t cm, mclBnFr *v, cp_t cp, apk_t apk, mclBnFr *r, mclBnFr *k, mclBnFr *r0, mclBnFr *N)
{
    mclBnG1 tmp, rg, vg, rp, kg, r0g, kapk, ng;
    int b1, b2, b3, b4, b5;

    // 验证承诺cm正确计算
    mclBnG1_mul(&rg, &G, r);
    b1 = mclBnG1_isEqual(&cm->c0, &rg);
    mclBnG1_mul(&vg, &G, v);
    mclBnG1_mul(&rp, &P, r);
    mclBnG1_add(&tmp, &vg, &rp);
    b2 = mclBnG1_isEqual(&cm->c1, &tmp);

    // 验证链接密文cp正确计算
    mclBnG1_mul(&kg, &G, k);
    b3 = mclBnG1_isEqual(&cp->cp0, &kg);
    mclBnG1_mul(&r0g, &G, r0);
    mclBnG1_mul(&kapk, &apk->x, k);
    mclBnG1_add(&tmp, &r0g, &kapk);
    b4 = mclBnG1_isEqual(&cp->cp1, &tmp);
    mclBnG1_mul(&ng, &G, N);

    // 验证链接标签tag正确计算
    b5 = mclBnG1_isEqual(&cp->tag, &ng);
    return b1 && b2 && b3 && b4 && b5;
}

/**
 * @brief   签名验证函数
 * @param   params  承诺 链接密文和标签 签名 集线器公钥 审计者公钥
 * @return  验证结果
 */
int vfAuth(commit_t cm, cp_t cp, signature_t sigma, vk_t vk, apk_t apk)
{
    if (mclBnG1_isZero(&sigma->s))
    {
        return 0;
    }

    mclBnFr e;
    mclBnGT tmp, zs_hat, gg_hat, cp0x0_hat, cp1x1_hat, c0x0_hat, c1x1_hat, gs_hat, sg_hat, ts_hat, gx0_hat, px1_hat, us_hat, apkx1_hat, vs_hat, gx1_hat;
    int b1, b2, b3, b4, b5;

    mclBn_pairing(&zs_hat, &sigma->z, &sigma->s_hat);
    mclBn_pairing(&gg_hat, &G, &G_hat);
    mclBn_pairing(&cp0x0_hat, &cp->cp0, &vk->x0_hat);
    mclBn_pairing(&cp1x1_hat, &cp->cp1, &vk->x1_hat);
    mclBn_pairing(&c0x0_hat, &cm->c0, &vk->x0_hat);
    mclBn_pairing(&c1x1_hat, &cm->c1, &vk->x1_hat);
    mclBnGT_mul(&tmp, &gg_hat, &cp0x0_hat);
    mclBnGT_mul(&tmp, &tmp, &cp1x1_hat);
    mclBnGT_mul(&tmp, &tmp, &c0x0_hat);
    mclBnGT_mul(&tmp, &tmp, &c1x1_hat);
    b1 = mclBnGT_isEqual(&zs_hat, &tmp);

    mclBn_pairing(&gs_hat, &G, &sigma->s_hat);
    mclBn_pairing(&sg_hat, &sigma->s, &G_hat);
    b2 = mclBnGT_isEqual(&gs_hat, &sg_hat);

    mclBn_pairing(&ts_hat, &sigma->t, &sigma->s_hat);
    mclBn_pairing(&gx0_hat, &G, &vk->x0_hat);
    mclBn_pairing(&px1_hat, &P, &vk->x1_hat);
    mclBnGT_mul(&tmp, &gx0_hat, &px1_hat);
    b3 = mclBnGT_isEqual(&ts_hat, &tmp);

    mclBn_pairing(&us_hat, &sigma->u, &sigma->s_hat);
    mclBn_pairing(&apkx1_hat, &apk->x, &vk->x1_hat);
    mclBnGT_mul(&tmp, &gx0_hat, &apkx1_hat);
    b4 = mclBnGT_isEqual(&us_hat, &tmp);

    mclBn_pairing(&vs_hat, &sigma->v, &sigma->s_hat);
    mclBn_pairing(&gx1_hat, &G, &vk->x1_hat);
    b5 = mclBnGT_isEqual(&vs_hat, &gx1_hat);

    return b1 && b2 && b3 && b4 && b5;
}

/**
 * @brief   证明验证函数
 * @param   params  证明 链接密文和标签 审计者公钥
 * @return  验证结果
 */
int vfProof(proof_t proof, cp_t cp, apk_t apk) {
    mclBnFr e;
    mclBnG1 tmp, a0, a1, a2, zkg, ecp0, zrg, zkapk, ecp1, zng, etag;

    // 计算a0, a1, a2
    mclBnG1_mul(&zkg, &G, &proof->zk);
    mclBnG1_mul(&ecp0, &cp->cp0, &proof->e);
    mclBnG1_sub(&a0, &zkg, &ecp0);
    mclBnG1_mul(&zrg, &G, &proof->zr);
    mclBnG1_mul(&zkapk, &apk->x, &proof->zk);
    mclBnG1_mul(&ecp1, &cp->cp1, &proof->e);
    mclBnG1_add(&tmp, &zrg, &zkapk);
    mclBnG1_sub(&a1, &tmp, &ecp1);
    mclBnG1_mul(&zng, &G, &proof->zn);
    mclBnG1_mul(&etag, &cp->tag, &proof->e);
    mclBnG1_sub(&a2, &zng, &etag);

    // 计算哈希值e'并比较
    mclBnG1 points[7] = {cp->cp0, cp->cp1, cp->tag, a0, a1, a2, apk->x};
    hashElementsToBigInt(&e, points, 7);
    return mclBnFr_isEqual(&e, &proof->e);
}

/**
 * @brief   认证承诺随机化函数
 * @param   params  随机化承诺 随机化签名 随机化链接密文和标签 证明 审计者公钥 原承诺 原签名 原链接密文和标签 随机数r' 随机数k' 随机数k 随机数r0 随机数N
 * @return  无
 */
void rdmAC(commit_t cm_, signature_t sigma_, cp_t cp_, proof_t proof, apk_t apk, commit_t cm, signature_t sigma, cp_t cp, mclBnFr *r_, mclBnFr *k_, mclBnFr *k, mclBnFr *r0, mclBnFr *N)
{
    // 随机数
    mclBnFr s, s_inv, rr, rk, rn;
    // 承诺和密文中间量
    mclBnG1 tmp, k_g, r_g, k_apk, r_p;
    // 签名中间量
    mclBnG1 z1, z2, z3, r_t, k_u, r_v;
    // 证明中间量
    mclBnG1 a0, a1, a2, rrg, rkapk;
    mclBnFr r0r_, kk_, Nr_, er0r_, ekk_, eNr_;

    // 随机选取k', r'计算随机化链接密文cp'
    mclBnFr_setByCSPRNG(k_);
    mclBnFr_setByCSPRNG(r_);
    // 计算随机化链接密文cp'
    mclBnG1_mul(&k_g, &G, k_);
    mclBnG1_add(&cp_->cp0, &cp->cp0, &k_g);
    mclBnG1_mul(&r_g, &G, r_);
    mclBnG1_mul(&k_apk, &apk->x, k_);
    mclBnG1_add(&tmp, &r_g, &k_apk);
    mclBnG1_add(&cp_->cp1, &cp->cp1, &tmp);
    
    // 计算随机化链接标签tag'
    mclBnG1_add(&cp_->tag, &cp->tag, &r_g);

    // 计算随机化承诺cm'
    mclBnG1_add(&cm_->c0, &cm->c0, &r_g);
    mclBnG1_mul(&r_p, &P, r_);
    mclBnG1_add(&cm_->c1, &cm->c1, &r_p);

    // 随机选取s'计算随机化签名sigma'
    mclBnFr_setByCSPRNG(&s);
    mclBnFr_inv(&s_inv, &s);
    // 计算签名sigma'中的z'
    mclBnG1_mul(&r_t, &sigma->t, r_);
    mclBnG1_mul(&k_u, &sigma->u, k_);
    mclBnG1_mul(&r_v, &sigma->v, r_);
    mclBnG1_add(&z1, &sigma->z, &r_t);
    mclBnG1_add(&z2, &z1, &k_u);
    mclBnG1_add(&z3, &z2, &r_v);
    mclBnG1_mul(&sigma_->z, &z3, &s_inv);
    // 计算签名sigma'中的s'
    mclBnG1_mul(&sigma_->s, &sigma->s, &s);
    // 计算签名sigma'中的s'_hat
    mclBnG2_mul(&sigma_->s_hat, &sigma->s_hat, &s);
    // 计算签名sigma'中的t'
    mclBnG1_mul(&sigma_->t, &sigma->t, &s_inv);
    // 计算签名sigma'中的u'
    mclBnG1_mul(&sigma_->u, &sigma->u, &s_inv);
    // 计算签名sigma'中的v'
    mclBnG1_mul(&sigma_->v, &sigma->v, &s_inv);

    // 随机选取rr, rk, rn计算证明proof
    mclBnFr_setByCSPRNG(&rr);
    mclBnFr_setByCSPRNG(&rk);
    mclBnFr_setByCSPRNG(&rn);
    // 计算a0, a1, a2
    mclBnG1_mul(&a0, &G, &rk);
    mclBnG1_mul(&rrg, &G, &rr);
    mclBnG1_mul(&rkapk, &apk->x, &rk);
    mclBnG1_add(&a1, &rrg, &rkapk);
    mclBnG1_mul(&a2, &G, &rn);
    // 计算哈希值
    mclBnG1 points[7] = {cp_->cp0, cp_->cp1, cp_->tag, a0, a1, a2, apk->x};
    hashElementsToBigInt(&proof->e, points, 7);
    // 计算zr, zk, zn
    mclBnFr_add(&r0r_, r0, r_);
    mclBnFr_mul(&er0r_, &proof->e, &r0r_);
    mclBnFr_add(&proof->zr, &rr, &er0r_);
    mclBnFr_add(&kk_, k, k_);
    mclBnFr_mul(&ekk_, &proof->e, &kk_);
    mclBnFr_add(&proof->zk, &rk, &ekk_);
    mclBnFr_add(&Nr_, N, r_);
    mclBnFr_mul(&eNr_, &proof->e, &Nr_);
    mclBnFr_add(&proof->zn, &rn, &eNr_);
}

/**
 * @brief   认证承诺更新函数
 * @param   params  新承诺 新签名 原承诺 链接密文和标签 交易金额 集线器私钥 审计者公钥
 * @return  无
 */
void updAC(commit_t cm_new, signature_t sigma_new, commit_t cm, cp_t cp, mclBnFr *amt, sk_t sk, apk_t apk)
{
    // 随机数
    mclBnFr s_new, s_new_inv;
    // 承诺中间量
    mclBnG1 tmp, ag;
    // 签名中间量
    mclBnG1 z, x0c0, x1c1, x0cp0, x1cp1, z1, z2, z3;
    mclBnG1 t, u, x0g, x1p, x1apk, x1g;

    // 计算承诺cm_new
    cm_new->c0 = cm->c0;
    mclBnG1_mul(&ag, &G, amt);
    mclBnG1_add(&cm_new->c1, &cm->c1, &ag);

    // 随机选取s_new计算签名sigma_new
    mclBnFr_setByCSPRNG(&s_new);
    mclBnFr_inv(&s_new_inv, &s_new);
    // 计算签名sigma_new中的z
    mclBnG1_mul(&x0c0, &cm_new->c0, &sk->x0);
    mclBnG1_mul(&x1c1, &cm_new->c1, &sk->x1);
    mclBnG1_mul(&x0cp0, &cp->cp0, &sk->x0);
    mclBnG1_mul(&x1cp1, &cp->cp1, &sk->x1);
    mclBnG1_add(&z1, &x0c0, &x1c1);
    mclBnG1_add(&z2, &x0cp0, &x1cp1);
    mclBnG1_add(&z3, &z1, &z2);
    mclBnG1_add(&z, &z3, &G);
    mclBnG1_mul(&sigma_new->z, &z, &s_new_inv);
    // 计算签名sigma_new中的s
    mclBnG1_mul(&sigma_new->s, &G, &s_new);
    // 计算签名sigma_new中的s_hat
    mclBnG2_mul(&sigma_new->s_hat, &G_hat, &s_new);
    // 计算签名sigma_new中的t
    mclBnG1_mul(&x0g, &G, &sk->x0);
    mclBnG1_mul(&x1p, &P, &sk->x1);
    mclBnG1_add(&t, &x0g, &x1p);
    mclBnG1_mul(&sigma_new->t, &t, &s_new_inv);
    // 计算签名sigma中的u
    mclBnG1_mul(&x1apk, &apk->x, &sk->x1);
    mclBnG1_add(&u, &x0g, &x1apk);
    mclBnG1_mul(&sigma_new->u, &u, &s_new_inv);
    // 计算签名sigma中的v
    mclBnG1_mul(&x1g, &G, &sk->x1);
    mclBnG1_mul(&sigma_new->v, &x1g, &s_new_inv);
}

/**
 * @brief   认证承诺更新验证函数
 * @param   params  原承诺 交易金额 链接密文和标签 新承诺 新签名 集线器公钥 审计者公钥
 * @return  验证结果
 */
int vfUpd(commit_t cm, mclBnFr *amt, cp_t cp, commit_t cm_new, signature_t sigma_new, vk_t vk, apk_t apk)
{
    if (mclBnG1_isZero(&sigma_new->s))
    {
        return 0;
    }

    mclBnG1 tmp, ag;
    int b1, b2, b3;

    b1 = mclBnG1_isEqual(&cm->c0, &cm_new->c0);
    mclBnG1_mul(&ag, &G, amt);
    mclBnG1_add(&tmp, &ag, &cm->c1);
    b2 = mclBnG1_isEqual(&cm_new->c1, &tmp);
    b3 = vfAuth(cm_new, cp, sigma_new, vk, apk);
    return b1 && b2 && b3;
}

/**
 * @brief   链接交易函数
 * @param   params  链接密文和标签1 链接密文和标签2 证明 审计者私钥 审计者公钥
 * @return  验证结果
 */
int linkCP(cp_t cp1, cp_t cp2, proof_t proof, ask_t ask, apk_t apk) {
    mclBnG1 cp10ask, cp20ask, ep1, ep2, left, right;
    int b1, b2;

    // 验证证明
    b1 = vfProof(proof, cp2, apk);

    // 解密链接密文
    mclBnG1_mul(&cp10ask, &cp1->cp0, &ask->x);
    mclBnG1_sub(&ep1, &cp1->cp1, &cp10ask);
    mclBnG1_mul(&cp20ask, &cp2->cp0, &ask->x);
    mclBnG1_sub(&ep2, &cp2->cp1, &cp20ask);

    // 验证交易链接
    mclBnG1_sub(&left, &ep2, &ep1);
    mclBnG1_sub(&right, &cp2->tag, &cp1->tag);
    b2 = mclBnG1_isEqual(&left, &right);

    return b1 && b2;
}
