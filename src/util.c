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

void util_function()
{
    printf("Util function called.\n");
}

void init_sys()
{
    // 初始化mcl使用的曲线
    mclBn_init(MCL_BN_SNARK1, MCLBN_COMPILED_TIME_VAR);
    // 初始化生成元G, P, G_hat
    mclBnG1_setStr(&G, G_STR, strlen(G_STR), 10);
    mclBnG1_setStr(&P, P_STR, strlen(P_STR), 10);
    mclBnG2_setStr(&G_hat, G_HAT_STR, strlen(G_HAT_STR), 10);
}

void keyGen(sk_t sk, vk_t vk)
{
    // 选取私钥sk
    mclBnFr_setByCSPRNG(&sk->x0);
    mclBnFr_setByCSPRNG(&sk->x1);
    // 计算公钥vk
    mclBnG2_mul(&vk->x0_hat, &G_hat, &sk->x0);
    mclBnG2_mul(&vk->x1_hat, &G_hat, &sk->x1);
}

void authCom(commit_t cm, signature_t sigma, mclBnFr *v, sk_t sk, mclBnFr *r)
{
    mclBnG1 vg, rp;
    mclBnFr s, s_inv;
    mclBnG1 z, z1, z2, z3, t;
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
    mclBnG1_mul(&z1, &cm->c0, &sk->x0);
    mclBnG1_mul(&z2, &cm->c1, &sk->x1);
    mclBnG1_add(&z3, &z1, &G);
    mclBnG1_add(&z, &z3, &z2);
    mclBnG1_mul(&sigma->z, &z, &s_inv);
    // 计算签名sigma中的s
    mclBnG1_mul(&sigma->s, &G, &s);
    // 计算签名sigma中的s_hat
    mclBnG2_mul(&sigma->s_hat, &G_hat, &s);
    // 计算签名sigma中的t
    mclBnG1_mul(&z1, &G, &sk->x0);
    mclBnG1_mul(&z2, &P, &sk->x1);
    mclBnG1_add(&z3, &z1, &z2);
    mclBnG1_mul(&sigma->t, &z3, &s_inv);
}

int vfCom(commit_t cm, mclBnFr *v, mclBnFr *r)
{
    mclBnG1 rg, vg, rp, tmp;
    int b1, b2;
    mclBnG1_mul(&rg, &G, r);
    b1 = mclBnG1_isEqual(&cm->c0, &rg);
    mclBnG1_mul(&vg, &G, v);
    mclBnG1_mul(&rp, &P, r);
    mclBnG1_add(&tmp, &vg, &rp);
    b2 = mclBnG1_isEqual(&cm->c1, &tmp);
    return b1 && b2;
}

int vfAuth(commit_t cm, signature_t sigma, vk_t vk)
{
    if (mclBnG1_isZero(&sigma->s))
    {
        return 0;
    }
    mclBnGT zs_hat, gg_hat, c0x0_hat, c1x1_hat, gs_hat, sg_hat, ts_hat, gx0_hat, px1_hat;
    mclBnGT tmp1, tmp2;
    int b1, b2, b3;
    mclBn_pairing(&zs_hat, &sigma->z, &sigma->s_hat);
    mclBn_pairing(&gg_hat, &G, &G_hat);
    mclBn_pairing(&c0x0_hat, &cm->c0, &vk->x0_hat);
    mclBn_pairing(&c1x1_hat, &cm->c1, &vk->x1_hat);
    mclBnGT_mul(&tmp1, &gg_hat, &c0x0_hat);
    mclBnGT_mul(&tmp2, &tmp1, &c1x1_hat);
    b1 = mclBnGT_isEqual(&zs_hat, &tmp2);
    mclBn_pairing(&gs_hat, &G, &sigma->s_hat);
    mclBn_pairing(&sg_hat, &sigma->s, &G_hat);
    b2 = mclBnGT_isEqual(&gs_hat, &sg_hat);
    mclBn_pairing(&ts_hat, &sigma->t, &sigma->s_hat);
    mclBn_pairing(&gx0_hat, &G, &vk->x0_hat);
    mclBn_pairing(&px1_hat, &P, &vk->x1_hat);
    mclBnGT_mul(&tmp1, &gx0_hat, &px1_hat);
    b3 = mclBnGT_isEqual(&ts_hat, &tmp1);
    return b1 && b2 && b3;
}

void rdmAC(commit_t cm_, signature_t sigma_, commit_t cm, signature_t sigma, mclBnFr *r_)
{
    mclBnG1 r_g, r_p, r_t, z_;
    mclBnFr s_, s_inv_;
    // 随机选取r_计算承诺cm_
    mclBnFr_setByCSPRNG(r_);
    // 计算承诺cm_
    mclBnG1_mul(&r_g, &G, r_);
    mclBnG1_add(&cm_->c0, &cm->c0, &r_g);
    mclBnG1_mul(&r_p, &P, r_);
    mclBnG1_add(&cm_->c1, &cm->c1, &r_p);
    // 随机选取s_计算签名sigma_
    mclBnFr_setByCSPRNG(&s_);
    mclBnFr_inv(&s_inv_, &s_);
    // 计算签名sigma_中的z
    mclBnG1_mul(&r_t, &sigma->t, r_);
    mclBnG1_add(&z_, &sigma->z, &r_t);
    mclBnG1_mul(&sigma_->z, &z_, &s_inv_);
    // 计算签名sigma_中的s
    mclBnG1_mul(&sigma_->s, &sigma->s, &s_);
    // 计算签名sigma_中的s_hat
    mclBnG2_mul(&sigma_->s_hat, &sigma->s_hat, &s_);
    // 计算签名sigma_中的t
    mclBnG1_mul(&sigma_->t, &sigma->t, &s_inv_);
}

void updAC(commit_t cm_new, signature_t sigma_new, commit_t cm, mclBnFr *amt, sk_t sk)
{
    mclBnG1 ag, x0c0, x1c1, tmp, x0g, x1p;
    mclBnFr s_new, s_new_inv;
    // 计算承诺cm_new
    cm_new->c0 = cm->c0;
    mclBnG1_mul(&ag, &G, amt);
    mclBnG1_add(&cm_new->c1, &cm->c1, &ag);
    // 随机选取s_new计算签名sigma_new
    mclBnFr_setByCSPRNG(&s_new);
    mclBnFr_inv(&s_new_inv, &s_new);
    // 计算签名sigma_new中的z
    mclBnG1_mul(&x0c0, &cm->c0, &sk->x0);
    mclBnG1_mul(&x1c1, &cm_new->c1, &sk->x1);
    mclBnG1_add(&tmp, &x0c0, &x1c1);
    mclBnG1_add(&tmp, &tmp, &G);
    mclBnG1_mul(&sigma_new->z, &tmp, &s_new_inv);
    // 计算签名sigma_new中的s
    mclBnG1_mul(&sigma_new->s, &G, &s_new);
    // 计算签名sigma_new中的s_hat
    mclBnG2_mul(&sigma_new->s_hat, &G_hat, &s_new);
    // 计算签名sigma_new中的t
    mclBnG1_mul(&x0g, &G, &sk->x0);
    mclBnG1_mul(&x1p, &P, &sk->x1);
    mclBnG1_add(&tmp, &x0g, &x1p);
    mclBnG1_mul(&sigma_new->t, &tmp, &s_new_inv);
}

int vfUpd(commit_t cm, mclBnFr *amt, commit_t cm_new, signature_t sigma_new, vk_t vk)
{
    if (mclBnG1_isZero(&sigma_new->s))
    {
        return 0;
    }
    mclBnG1 ag, tmp;
    int b1, b2, b3;
    b1 = mclBnG1_isEqual(&cm->c0, &cm_new->c0);
    mclBnG1_mul(&ag, &G, amt);
    mclBnG1_add(&tmp, &ag, &cm->c1);
    b2 = mclBnG1_isEqual(&cm_new->c1, &tmp);
    b3 = vfAuth(cm_new, sigma_new, vk);
    return b1 && b2 && b3;
}
