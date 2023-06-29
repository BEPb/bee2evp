/*
*******************************************************************************
\file belt_pbkdf.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief The Belt-based PBKDF
\created 2015.01.19
\version 2021.02.18
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <bee2/core/blob.h>
#include <bee2/crypto/belt.h>
#include "bee2evp/bee2evp.h"

/*
*******************************************************************************
Алгоритм belt-pbkdf --- это реализация схемы PBKDF2 на основе алгоритмов belt.
Подробности -- в PKCS#5, а также в СТБ 34.101.45 (Е.2).

Для подключения belt-pbkdf следует:
1	Выполнить регистрацию, вызвав EVP_PBE_alg_add_type(EVP_PBE_TYPE_PRF, 
	NID_belt_hmac, -1, NID_belt_hash, 0).
2	В ctrl-функциях алгоритмов шифрования, ключ которых будет строиться по 
	паролю, возвращать NID_belt_hmac в ответ на команду EVP_CTRL_PBE_PRF_NID.
	
Параметрами belt-pbkdf являются число итераций и синхропосылка (соль).
В СТБ 34.101.45 рекомендуется использовать не менее чем 64-битовую 
синхропосылку (соль) и не менее чем 10000 итераций. 

В evp.h заданы стандартные для OpenSSL длина синхропосылки и число итераций:
	#define PKCS5_SALT_LEN		8
	#define PKCS5_DEFAULT_ITER	2048
Таким образом, рекомендации по длине синхропосылки поддерживаются, а по числу 
итераций -- нет. Рекомендации можно выполнить, если зарегистрировать 
функцию интерфейса EVP_PBE_KEYGEN (объявленного в evp.h), которая их 
поддерживает.

К сожалению, эта функция не получает управления при работе через командный 
интерфейс OpenSSL. Возможный выход (через патч) -- расширение массива 
builtin_pbe, объявленного в crypto/evp/evp_pbe.c.

\remark По мотивам openssl/crypto/asn1/p5_pbev2.c, 
openssl/crypto/evp/p5_crpt2.c.

todo: полноценное встраивание (?)
*******************************************************************************
*/

const char OID_belt_pbkdf[] = "1.2.112.0.2.0.34.101.31.111";
const char SN_belt_pbkdf[] = "belt-pbkdf";
const char LN_belt_pbkdf[] = "belt-pbkdf";
#define NID_belt_pbkdf OBJ_sn2nid(SN_belt_pbkdf)

int evpBeltPBKDF_keyivgen(EVP_CIPHER_CTX* ctx, const char* pass, int passlen,
	ASN1_TYPE* param, const EVP_CIPHER* c, const EVP_MD* md, int en_de)
{
	int key_len;
	const octet* der;
	int der_len;
	PBKDF2PARAM* kdf = 0;
	octet* salt;
	int salt_len;
	long iter;
	blob_t key = 0;
	int ret = 0;
	// определить длину ключа
	if (!ctx || !EVP_CIPHER_CTX_cipher(ctx))
		return 0;
	key_len = EVP_CIPHER_CTX_key_length(ctx);
	if (key_len > 32)
		return 0;
	// декодировать параметры
	if(!param || param->type != V_ASN1_SEQUENCE)
		return 0;
	der = param->value.sequence->data;
	der_len = param->value.sequence->length;
	kdf = d2i_PBKDF2PARAM(0, &der, der_len);
	if(!kdf)
		return 0;
	// проверить параметры
	if(kdf->keylength && ASN1_INTEGER_get(kdf->keylength) != (int)key_len ||
		OBJ_obj2nid(kdf->prf->algorithm) != NID_belt_hmac ||
		kdf->prf->parameter->type != V_ASN1_NULL ||
		kdf->salt->type != V_ASN1_OCTET_STRING)
		goto err;
	// настроить синхропосылку
	salt = kdf->salt->value.octet_string->data;
	salt_len = kdf->salt->value.octet_string->length;
	if (salt_len < 8)
	{
		salt_len = 8;
		if (!ASN1_OCTET_STRING_set(kdf->salt->value.octet_string, 0, salt_len))
			goto err;
		salt = kdf->salt->value.octet_string->data;
		if (RAND_bytes(salt, salt_len) < 0)
			goto err;
	}
	// настроить число итераций
	iter = ASN1_INTEGER_get(kdf->iter);
	if (iter < 10000)
	{
		iter = 10000;
		if (!ASN1_INTEGER_set(kdf->iter, iter))
			goto err;
	}
	// построить ключ
	key = blobCreate(32);
	if (!key)
		goto err;
	if (beltPBKDF2((octet*)key, (const octet*)pass, passlen, 
		(size_t)iter, salt, salt_len) != ERR_OK)
		goto err;
	// задать ключ
	ret = EVP_CipherInit_ex(ctx, 0, 0, (const octet*)key, 0, en_de);
err:
	blobClose(key);
	PBKDF2PARAM_free(kdf);
	return ret;
}

/*
*******************************************************************************
Регистрация
*******************************************************************************
*/

static int belt_pbkdf_nids[128];
static int belt_pbkdf_count;

#define BELT_PBKDF_REG(name, tmp)\
	(((tmp = NID_##name) != NID_undef) ?\
		belt_pbkdf_nids[belt_pbkdf_count++] = tmp :\
		(((tmp = OBJ_create(OID_##name, SN_##name, LN_##name)) > 0) ?\
			belt_pbkdf_nids[belt_pbkdf_count++] = tmp : NID_undef))

/*
*******************************************************************************
Подключение / закрытие
*******************************************************************************
*/

int evpBeltPBKDF_bind(ENGINE* e)
{
	int tmp;
	// зарегистрировать алгоритмы и получить nid'ы
	if (BELT_PBKDF_REG(belt_pbkdf, tmp) == NID_undef)
		return 0;
	// все нормально
	return 1;
}

void evpBeltPBKDF_finish()
{
}
