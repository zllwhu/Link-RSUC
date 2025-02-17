/**
 * @file    types.h
 * @brief   类型头文件：定义Link-RSUC方案中的数据结构及其内存管理宏
 * @author  赵路路
 * @date    2025-02-16
 * @version 1.0
 *
 * 修改记录：
 * - 2025-02-16 赵路路：创建工程，编译测试
 * - 2025-02-17 赵路路：规范代码注释
 */

#ifndef TYPES_H
#define TYPES_H

#include <mcl/bn_c256.h>
#include <stdlib.h>

/**
 * @brief   记录集线器私钥的结构体
 */
typedef struct
{
    mclBnFr x0, x1;
} sk_st;

typedef sk_st *sk_t;

#define sk_new(params)                  \
    do                                  \
    {                                   \
        params = malloc(sizeof(sk_st)); \
    } while (0)

#define sk_free(params) \
    do                  \
    {                   \
        free(params);   \
        params = NULL;  \
    } while (0)

/**
 * @brief   记录集线器公钥的结构体
 */
typedef struct
{
    mclBnG2 x0_hat, x1_hat;
} vk_st;

typedef vk_st *vk_t;

#define vk_new(params)                  \
    do                                  \
    {                                   \
        params = malloc(sizeof(vk_st)); \
    } while (0)

#define vk_free(params) \
    do                  \
    {                   \
        free(params);   \
        params = NULL;  \
    } while (0)

/**
 * @brief   记录审计者私钥的结构体
 */
typedef struct
{
    mclBnFr x;
} ask_st;

typedef ask_st *ask_t;

#define ask_new(params)                     \
    do                                      \
    {                                       \
        params = malloc(sizeof(ask_st));    \
    } while (0);
    
/**
 * @brief   记录审计者公钥的结构体
 */

/**
 * @brief   记录承诺的结构体
 */
typedef struct
{
    mclBnG1 c0, c1;
} commit_st;

typedef commit_st *commit_t;

#define commit_new(params)                  \
    do                                      \
    {                                       \
        params = malloc(sizeof(commit_st)); \
    } while (0)

#define commit_free(params) \
    do                      \
    {                       \
        free(params);       \
        params = NULL;      \
    } while (0)

/**
 * @brief   记录签名的结构体
 */
typedef struct
{
    mclBnG1 z, s, t;
    mclBnG2 s_hat;
} signature_st;

typedef signature_st *signature_t;

#define signature_new(params)                  \
    do                                         \
    {                                          \
        params = malloc(sizeof(signature_st)); \
    } while (0)

#define signature_free(params) \
    do                         \
    {                          \
        free(params);          \
        params = NULL;         \
    } while (0)

#endif
