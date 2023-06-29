/*
*******************************************************************************
\file bee2evp_lcl.h
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Internal definitions
\created 2013.11.11
\version 2021.02.18
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#ifndef __BEE2EVP_LCL_H
#define __BEE2EVP_LCL_H

#include <openssl/evp.h>
#include <bee2/core/blob.h>
#include <bee2/crypto/bign.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
*******************************************************************************
Блобы EVP_CIPHER_CTX

В контексте EVP_CIPHER_CTX состояние алгоритма шифрования размещается в блобе
(контролируемом фрагменте памяти).

\todo Разобраться с блобами в EVP_MD_CTX. Здесь все намного сложнеe:
1. Закрыт set-доступ к указателю на пользовательские данные (md_data).
2. OpenSSL не всегда гарантирует выделение памяти под указатель
   EVP_MD_CTX::md_data, который возвращается функцией EVP_MD_CTX_md_data()
   (см. EVP_MD_CTX_copy_ex() при установке флага EVP_MD_CTX_FLAG_REUSE).
3. При копировании контекстов EVP_MD_CTX сначала механически копируются
   пользовательские данные md_data, в том числе блобы. Механическое копирование
   указателей приводит к ошибкам освобождения памяти.
*******************************************************************************
*/

blob_t EVP_CIPHER_CTX_get_blob(const EVP_CIPHER_CTX* ctx);
int EVP_CIPHER_CTX_set_blob(EVP_CIPHER_CTX* ctx, const blob_t blob);
int EVP_CIPHER_CTX_copy_blob(EVP_CIPHER_CTX* to, const EVP_CIPHER_CTX* from);

/*
*******************************************************************************
Belt
*******************************************************************************
*/

int evpBeltPBKDF_keyivgen(EVP_CIPHER_CTX* ctx, const char* pass, int passlen,
	ASN1_TYPE* param, const EVP_CIPHER* c, const EVP_MD* md, int en_de);

/*
*******************************************************************************
Bign

\remark В функциях evpBign_asn1_d2i_params() / evpBign_asn1_i2d_params() 
флаг EVP_BIGN_PKEY_ENC_PARAMS_SPECIFIED в key->enc_flags указывает на желаемую
специфицированность параметров при кодировании. Если флаг установлен, 
то параметры обязательно будут специфироваться. Если флаг снят, то параметры 
могут специфицироваться, если они не распознаны как именованные. Актуальный 
признак специфицированности возвращается через переменную specified.
*******************************************************************************
*/

typedef struct bign_key
{
	bign_params params[1];		/*< долговременные параметры */
	octet privkey[64];			/*< личный ключ */
	octet pubkey[128];			/*< открытый ключ */
	u8 flags;					/*< флаги */
	int hash_nid;				/*< рекомендуемый алгоритм хэширования */
} bign_key;

int evpBign_eq_params(const bign_params* params1, const bign_params* params2);
int evpBign_params2nid(const bign_params* params);
int evpBign_nid2params(bign_params* params, int nid);

int evpBign_asn1_d2i_params(bign_key* key, bool_t* specified, 
	const octet** in, long len);
int evpBign_asn1_i2d_params(octet** out, bool_t* specified, 
	const bign_key* key);
int evpBign_asn1_o2i_pubkey(bign_key* key, const octet** in, long len);
int evpBign_asn1_i2o_pubkey(octet** out, const bign_key* key);

/*
*******************************************************************************
Подключение модулей
*******************************************************************************
*/

int evpBeltCipher_bind(ENGINE* e);
int evpBeltMD_bind(ENGINE* e);
int evpBelt_ameth_bind(ENGINE* e);
int evpBelt_pmeth_bind(ENGINE* e);
int evpBeltPBKDF_bind(ENGINE* e);
int evpBeltTLS_bind(ENGINE* e);
int evpBign_ameth_bind(ENGINE* e);
int evpBign_pmeth_bind(ENGINE* e);
int evpBash_bind(ENGINE* e);

/*
*******************************************************************************
Закрытие модулей
*******************************************************************************
*/

void evpBeltCipher_finish();
void evpBeltMD_finish();
void evpBelt_ameth_finish();
void evpBelt_pmeth_finish();
void evpBeltPBKDF_finish();
void evpBeltTLS_finish();
void evpBign_ameth_finish();
void evpBign_pmeth_finish();
void evpBash_finish();

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2EVP_LCL_H */
