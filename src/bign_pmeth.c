/*
*******************************************************************************
\file bign_pmeth.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Methods for bign-pubkey
\created 2014.10.06
\version 2021.04.26
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <bee2/core/blob.h>
#include <bee2/core/der.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bake.h>
#include <bee2/crypto/bign.h>
#include "bee2evp/bee2evp.h"
#include "bee2evp_lcl.h"

/*
*******************************************************************************
Методы ключа bign

Алгоритмы ЭЦП и транспорта ключа подключаются как методы ключа bign,
через структуру EVP_PKEY_METHOD. Методы ключа дополнительно включают протокол
Диффи -- Хеллмана, определенный в СТБ 34.101.66.

\remark По мотивам схемы подключения EC (openssl/crypto/cmac/ec_pmeth.c).

\remark Ключ в EVP_PKEY очищается в функции EVP_PKEY_free через 
вызов EVP_PKEY::ameth->pkey_free.

\remark В момент вызова ctrl-функций ключ (bign_key) еще не создан, создан
только контекст его создания (bign_pkey_ctx).

\remark Команды EVP_PKEY_CTRL_MD, EVP_PKEY_GET_MD отвечают за установку / 
чтение идентификатора алгоритма хэширования, который используется в
алгоритмах ЭЦП. Идентификатор по умолчанию определяется с помощью команды
ASN1_PKEY_CTRL_DEFAULT_MD_NID (модуль bign_ameth).

\remark Не тестировались:
	evpBign_pkey_kdf_derive.
*******************************************************************************
*/

/* bign algorithms */
const char OID_bign_with_hspec[] = "1.2.112.0.2.0.34.101.45.11";
const char SN_bign_with_hspec[] = "bign-with-hspec";
const char LN_bign_with_hspec[] = "bign-with-hspec";

const char OID_bign_with_hbelt[] = "1.2.112.0.2.0.34.101.45.12";
const char SN_bign_with_hbelt[] = "bign-with-hbelt";
const char LN_bign_with_hbelt[] = "bign-with-hbelt";

const char OID_bign_with_bash256[] = "1.2.112.0.2.0.34.101.45.13";
const char SN_bign_with_bash256[] = "bign-with-bash256";
const char LN_bign_with_bash256[] = "bign-with-bash256";

const char OID_bign_with_bash384[] = "1.2.112.0.2.0.34.101.45.14";
const char SN_bign_with_bash384[] = "bign-with-bash384";
const char LN_bign_with_bash384[] = "bign-with-bash384";

const char OID_bign_with_bash512[] = "1.2.112.0.2.0.34.101.45.15";
const char SN_bign_with_bash512[] = "bign-with-bash512";
const char LN_bign_with_bash512[] = "bign-with-bash512";

const char OID_bign_keytransport[] = "1.2.112.0.2.0.34.101.45.41";
const char SN_bign_keytransport[] = "bign-keytransport";
const char LN_bign_keytransport[] = "bign-keytransport";

/* bign-pubkey */
const char OID_bign_pubkey[] = "1.2.112.0.2.0.34.101.45.2.1";
const char SN_bign_pubkey[] = "bign-pubkey";
const char LN_bign_pubkey[] = "bign-pubkey";

/* bign-curve256v1 */
const char OID_bign_curve256v1[] = "1.2.112.0.2.0.34.101.45.3.1";
const char SN_bign_curve256v1[] = "bign-curve256v1";
const char LN_bign_curve256v1[] = "bign-curve256v1";

/* bign-curve384v1 */
const char OID_bign_curve384v1[] = "1.2.112.0.2.0.34.101.45.3.2";
const char SN_bign_curve384v1[] = "bign-curve384v1";
const char LN_bign_curve384v1[] = "bign-curve384v1";

/* bign-curve512v1 */
const char OID_bign_curve512v1[] = "1.2.112.0.2.0.34.101.45.3.3";
const char SN_bign_curve512v1[] = "bign-curve512v1";
const char LN_bign_curve512v1[] = "bign-curve512v1";

/* bign-primefield */
const char OID_bign_primefield[] = "1.2.112.0.2.0.34.101.45.4.1";
const char SN_bign_primefield[] = "bign-primefield";
const char LN_bign_primefield[] = "bign-primefield";

/*
*******************************************************************************
Контекст ключа bign
*******************************************************************************
*/

typedef struct bign_pkey_ctx
{
	int params_nid;		/*< идентификатор параметров */	
	int hash_nid;		/*< рекомендуемый хэш-алгоритм для ЭЦП */
	u8 flags;			/*< флаги */
	const EVP_MD* md;	/*< алгоритм хэширования для ЭЦП */
	blob_t kdf_ukm;		/*< данные для bake-kdf: ukm */
	int kdf_num;		/*< данные для bake-kdf: номер ключа */
} bign_pkey_ctx;

/*
*******************************************************************************
Управление ключом и его параметрами
*******************************************************************************
*/

static int evpBign_pkey_init(EVP_PKEY_CTX* ctx)
{
	bign_pkey_ctx* dctx;
	// создать контекст
	dctx = (bign_pkey_ctx*)blobCreate(sizeof(bign_pkey_ctx));
	if (!dctx)
		return 0;
	// инициализировать поля
	dctx->params_nid = NID_undef;
	dctx->hash_nid = NID_undef;
	dctx->flags = 0;
	dctx->md = 0;
	dctx->kdf_ukm = 0;
	dctx->kdf_num = 0;
	// установить контекст
	EVP_PKEY_CTX_set_data(ctx, dctx);
	return 1;
}

static int evpBign_pkey_copy(EVP_PKEY_CTX* dst, EVP_PKEY_CTX* src)
{
	bign_pkey_ctx* sctx;
	bign_pkey_ctx* dctx;
	// инициализировать контекст
	if (!evpBign_pkey_init(dst))
		return 0;
	// разобрать указатели
	sctx = (bign_pkey_ctx*)EVP_PKEY_CTX_get_data(src);
	dctx = (bign_pkey_ctx*)EVP_PKEY_CTX_get_data(dst);
	ASSERT(memIsValid(sctx, sizeof(bign_pkey_ctx)));
	ASSERT(memIsValid(dctx, sizeof(bign_pkey_ctx)));
	// переписать поля
	dctx->params_nid = sctx->params_nid;
	dctx->hash_nid = sctx->hash_nid;
	dctx->flags = sctx->flags;
	dctx->md = sctx->md;
	if (sctx->kdf_ukm)
	{
		dctx->kdf_ukm = blobCopy(0, sctx->kdf_ukm);
		if (!dctx->kdf_ukm)
			return 0;
	}
	else
		dctx->kdf_ukm = 0;
	dctx->kdf_num = sctx->kdf_num;
	return 1;
}

static void evpBign_pkey_cleanup(EVP_PKEY_CTX* ctx)
{
	bign_pkey_ctx* dctx = (bign_pkey_ctx*)EVP_PKEY_CTX_get_data(ctx);
	if (dctx)
	{
		ASSERT(memIsValid(dctx, sizeof(bign_pkey_ctx)));
		blobClose(dctx->kdf_ukm);
		blobClose(dctx);
	}
}

static int evpBign_pkey_paramgen(EVP_PKEY_CTX* ctx, EVP_PKEY* pkey)
{
	bign_pkey_ctx* dctx = (bign_pkey_ctx*)EVP_PKEY_CTX_get_data(ctx);
	bign_key* key;
	// разобрать указатели
	ASSERT(memIsValid(dctx, sizeof(bign_pkey_ctx)));
	// идентификатор параметров не задан?
	if (dctx->params_nid == NID_undef)
		return 0;
	// создать ключ
	key = (bign_key*)blobCreate(sizeof(bign_key));
	if (!key)
		return 0;
	// загрузить параметры
	if (!evpBign_nid2params(key->params, dctx->params_nid))
	{
		blobClose(key);
		return 0;
	}
	// установить флаги кодирования
	key->flags = dctx->flags;
	// установить ключ в контекст
	return EVP_PKEY_assign(pkey, NID_bign_pubkey, key);
}

static int evpBign_pkey_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY* pkey)
{
	bign_pkey_ctx* dctx = (bign_pkey_ctx*)EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY* ctx_pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	bign_key* key;
	// разобрать указатели
	ASSERT(memIsValid(dctx, sizeof(bign_pkey_ctx)));
	// генератор не работает? 
	if (!rngIsValid())
		return 0;
	// параметры могут передаваться либо в ctx->pkey (при чтении их из файла),
	// либо в dctx->params_nid (при задании через ctrl-вызовы)
	// ключ не создан и не задан идентификатор параметров?
	if (!ctx_pkey && !dctx->params_nid)
		return 0;
	// создать ключ
	key = (bign_key*)blobCreate(sizeof(bign_key));
	if (!key)
		return 0;
	// ключ уже есть в контексте
	if (ctx_pkey)
	{
		bign_key* old_key = (bign_key*)EVP_PKEY_get0(ctx_pkey);
		if (!old_key)
		{
			blobClose(key);
			return 0;
		}
		// переписать параметры
		memCopy(key->params, old_key->params, sizeof(bign_params));
	}
	// ключа нет в контексте
	else
	{
		// загрузить параметры
		if (!evpBign_nid2params(key->params, dctx->params_nid))
		{
			blobClose(key);
			return 0;
		}
	}
	// установить флаги кодирования
	key->flags = dctx->flags;
	// установить ключ в контекст
	if (EVP_PKEY_assign(pkey, NID_bign_pubkey, key) <= 0)
	{
		blobClose(key);
		return 0;
	}
	// сгенерировать пару ключей
	return bignGenKeypair(key->privkey, key->pubkey, key->params, 
		rngStepR, 0) == ERR_OK;
}

/*
*******************************************************************************
ЭЦП
*******************************************************************************
*/

static int evpBign_pkey_sign(EVP_PKEY_CTX* ctx, octet* sig, size_t* siglen, 
	const octet* tbs, size_t tbslen)
{
	bign_pkey_ctx* dctx = (bign_pkey_ctx*)EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	bign_key* key;
	const ASN1_OBJECT* obj;
	octet* der;
	size_t der_len;
	int ret;
	// разобрать указатели
	ASSERT(memIsValid(dctx, sizeof(bign_pkey_ctx)));
	ASSERT(pkey);
	key = (bign_key*)EVP_PKEY_get0(pkey);
	ASSERT(memIsValid(key, sizeof(bign_key)));
	// подготовить возврат подписи
	if (!sig)
	{
		*siglen = key->params->l / 8 * 3;
		return 1;
	}
	else if (*siglen < key->params->l / 8 * 3)
		return 0;
	*siglen = key->params->l / 8 * 3;
	// установить флаги подписи
	key->flags = dctx->flags;
	// проанализировать алгоритм хэширования 
	// и получить суффикс DER-кодировки oid в [obj->len]obj->data
	if (dctx->md == 0 ||
		EVP_MD_size(dctx->md) != (int)key->params->l / 4 || 
		EVP_MD_size(dctx->md) != (int)tbslen)
		return 0;
	if ((obj = OBJ_nid2obj(EVP_MD_type(dctx->md))) == 0)
		return 0;
	// построить полный DER-код
	der_len = derEnc(0, 6, OBJ_get0_data(obj), OBJ_length(obj));
	if (der_len == SIZE_MAX)
		return 0;
	der = (octet*)blobCreate(der_len);
	if (!der)
		return 0;
	derEnc(der, 6, OBJ_get0_data(obj), OBJ_length(obj));
	// подписать
	if ((key->flags & EVP_BIGN_PKEY_SIG_DETERMINISTIC) || !rngIsValid())
		ret = bignSign2(sig, key->params, der, der_len, tbs, 
			key->privkey, 0, 0) == ERR_OK;
	else
		ret = bignSign(sig, key->params, der, der_len, tbs, 
			key->privkey, rngStepR, 0) == ERR_OK;
	// завершить
	blobClose(der);
	return ret;
}

static int evpBign_pkey_verify(EVP_PKEY_CTX* ctx, const octet* sig, 
	size_t siglen, const octet* tbs, size_t tbslen)
{
	bign_pkey_ctx* dctx = (bign_pkey_ctx*)EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	bign_key* key;
	const ASN1_OBJECT* obj;
	octet* der;
	size_t der_len;
	int ret;
	// разобрать указатели
	ASSERT(memIsValid(dctx, sizeof(bign_pkey_ctx)));
	ASSERT(pkey);
	key = (bign_key*)EVP_PKEY_get0(pkey);
	ASSERT(memIsValid(dctx, sizeof(bign_key)));
	// проверить длину подписи
	if (siglen != key->params->l / 8 * 3)
		return 0;
	// установить флаги подписи
	key->flags = dctx->flags;
	// проанализировать алгоритм хэширования
	// и получить суффикс DER-кодировки oid в [obj->len]obj->data
	if (dctx->md == 0 ||
		EVP_MD_size(dctx->md) != (int)key->params->l / 4 ||
		EVP_MD_size(dctx->md) != (int)tbslen)
		return 0;
	if ((obj = OBJ_nid2obj(EVP_MD_type(dctx->md))) == 0)
		return 0;
	// построить полный DER-код
	der_len = derEnc(0, 6, OBJ_get0_data(obj), OBJ_length(obj));
	if (der_len == SIZE_MAX)
		return 0;
	der = (octet*)blobCreate(der_len);
	if (!der)
		return 0;
	derEnc(der, 6, OBJ_get0_data(obj), OBJ_length(obj));
	// проверить подпись
	ret = bignVerify(key->params, der, der_len, tbs, sig, 
		key->pubkey) == ERR_OK;
	// завершить
	blobClose(der);
	return ret;
}

/*
*******************************************************************************
Шифрование (транспорт) ключа
*******************************************************************************
*/

static int evpBign_pkey_encrypt(EVP_PKEY_CTX* ctx, octet* out, size_t* outlen,
	const octet* in, size_t inlen)
{
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	bign_key* key;
	// разобрать указатели
	ASSERT(pkey);
	key = (bign_key*)EVP_PKEY_get0(pkey);
	ASSERT(memIsValid(key, sizeof(bign_key)));
	// контроль входных данных и генератора
	if (inlen < 16 || !outlen || !rngIsValid())
		return 0;
	// установить длину выходных данных
	*outlen = inlen + 16 + key->params->l / 4;
	if (!out) 
		return 1;
	// зашифровать (установить защиту)
	return bignKeyWrap(out, key->params, in, inlen, 0, key->pubkey, 
		rngStepR, 0) == ERR_OK;
}

static int evpBign_pkey_decrypt(EVP_PKEY_CTX *ctx, octet* out, size_t* outlen,
	const octet* in, size_t inlen)
{
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	bign_key* key;
	// разобрать указатели
	ASSERT(pkey);
	key = (bign_key*)EVP_PKEY_get0(pkey);
	ASSERT(memIsValid(key, sizeof(bign_key)));
	// контроль входных данных
	if (inlen < 16 + 16 + key->params->l / 4 || !outlen)
		return 0;
	// установить длину выходных данных
	*outlen = inlen - 16 - key->params->l / 4;
	if (!out)
		return 1;
	// расшифровать (снять защиту)
	return bignKeyUnwrap(out, key->params, in, inlen, 0, 
		key->privkey) == ERR_OK;
}

/*
*******************************************************************************
Построение ключа
*******************************************************************************
*/

static int evpBign_pkey_derive(EVP_PKEY_CTX* ctx, octet* key, size_t* key_len)
{
	EVP_PKEY* mypkey = EVP_PKEY_CTX_get0_pkey(ctx);
	EVP_PKEY* peerpkey = EVP_PKEY_CTX_get0_peerkey(ctx);
	bign_key* mykey;
	bign_key* peerkey;
	// установлены свой и чужой ключи?
	if (!mypkey || !peerpkey)
		return 0;
	// однотипные ключи? с одинаковыми параметрами?
	if (EVP_PKEY_cmp(mypkey, peerpkey))
		return 0;
	// разобрать ключи
	mykey = (bign_key*)EVP_PKEY_get0(mypkey);
	peerkey = (bign_key*)EVP_PKEY_get0(peerpkey);
	ASSERT(memIsValid(mykey, sizeof(bign_key)));
	ASSERT(memIsValid(peerkey, sizeof(bign_key)));
	// возвратить максимальную длину ключа?
	if (!key)
	{
		*key_len = mykey->params->l / 2;
		return 1;
	}
	// построить ключ
	*key_len = MIN2(*key_len, mykey->params->l / 2);
	return bignDH(key, mykey->params, mykey->privkey, 
		peerkey->pubkey, *key_len) == ERR_OK;
}

static int evpBign_pkey_kdf_derive(EVP_PKEY_CTX* ctx, octet* key, 
	size_t* keylen)
{
	bign_pkey_ctx* dctx = (bign_pkey_ctx*)EVP_PKEY_CTX_get_data(ctx);
	octet* secret;
	size_t secret_len;
	err_t code;
	// разобрать указатели
	ASSERT(memIsValid(dctx, sizeof(bign_pkey_ctx)));
	// без bake-kdf?
	if ((dctx->flags & EVP_BIGN_PKEY_KDF_BAKE) == 0)
		return evpBign_pkey_derive(ctx, key, keylen);
	// возвратить максимальную длину ключа?
	if (!key)
	{
		*keylen = 32;
		return 1;
	}
	// построить ключ Диффи -- Хеллмана
	if (!evpBign_pkey_derive(ctx, 0, &secret_len))
		return 0;
	secret_len /= 2;
	if ((secret = (octet*)blobCreate(secret_len / 2)) == 0)
		return 0;
	if (!evpBign_pkey_derive(ctx, secret, &secret_len))
	{
		blobClose(secret);
		return 0;
	}
	// построить ключ bake-kdf
	*keylen = MIN2(*keylen, 32);
	code = bakeKDF(key, secret, secret_len, (octet*)dctx->kdf_ukm, 
		blobSize(dctx->kdf_ukm), dctx->kdf_num);
	// завершить
	blobClose(secret);
	return code == ERR_OK;
}

/*
*******************************************************************************
Ctrl-функции
*******************************************************************************
*/

#define EVP_BIGN_PKEY_CTRL_SET_PARAMS		(EVP_PKEY_ALG_CTRL + 1)
#define EVP_BIGN_PKEY_CTRL_SET_ENC_FLAGS	(EVP_PKEY_ALG_CTRL + 2)
#define EVP_BIGN_PKEY_CTRL_CLR_ENC_FLAGS	(EVP_PKEY_ALG_CTRL + 3)
#define EVP_BIGN_PKEY_CTRL_SET_SIG_FLAGS	(EVP_PKEY_ALG_CTRL + 4)
#define EVP_BIGN_PKEY_CTRL_CLR_SIG_FLAGS	(EVP_PKEY_ALG_CTRL + 5)
#define EVP_BIGN_PKEY_CTRL_SET_KDF_FLAGS	(EVP_PKEY_ALG_CTRL + 6)
#define EVP_BIGN_PKEY_CTRL_CLR_KDF_FLAGS	(EVP_PKEY_ALG_CTRL + 7)
#define EVP_BIGN_PKEY_CTRL_SET_KDF_UKM		(EVP_PKEY_ALG_CTRL + 8)
#define EVP_BIGN_PKEY_CTRL_SET_KDF_NUM		(EVP_PKEY_ALG_CTRL + 9)

static int evpBign_pkey_ctrl(EVP_PKEY_CTX* ctx, int type, int p1, void* p2)
{
	bign_pkey_ctx* dctx = (bign_pkey_ctx*)EVP_PKEY_CTX_get_data(ctx);
	bign_params params[1];
	const EVP_MD* md;
	// разобрать указатели
	ASSERT(memIsValid(dctx, sizeof(bign_pkey_ctx)));
	// обработать управляющий код
	switch (type)
	{
	case EVP_BIGN_PKEY_CTRL_SET_PARAMS:
		if (!evpBign_nid2params(params, p1))
			return -2;
		// нарушена совместимость с hash_nid?
		if (dctx->hash_nid != NID_undef)
		{
			md = EVP_get_digestbynid(p1);
			if ((int)params->l != EVP_MD_meth_get_result_size(md) * 4)
				return 0;
		}
		dctx->params_nid = p1;
		return 1;

	case EVP_BIGN_PKEY_CTRL_SET_ENC_FLAGS:
	case EVP_BIGN_PKEY_CTRL_SET_SIG_FLAGS:
	case EVP_BIGN_PKEY_CTRL_SET_KDF_FLAGS:
		dctx->flags |= (u8)p1;
		return 1;

	case EVP_BIGN_PKEY_CTRL_CLR_ENC_FLAGS:
	case EVP_BIGN_PKEY_CTRL_CLR_SIG_FLAGS:
	case EVP_BIGN_PKEY_CTRL_CLR_KDF_FLAGS:
		dctx->flags &= ~(u8)p1;
		return 1;

	case EVP_BIGN_PKEY_CTRL_SET_KDF_UKM:
		if ((dctx->flags & EVP_BIGN_PKEY_KDF_BAKE) == 0)
			return -2;
		if (p2)
		{
			if (p1 < 0)
				return -2;
			dctx->kdf_ukm = blobResize(dctx->kdf_ukm, (size_t)p1);
			if (!dctx->kdf_ukm)
				return -2;
			memCopy(dctx->kdf_ukm, p2, (size_t)p1);
		}
		else
		{
			blobClose(dctx->kdf_ukm);
			dctx->kdf_ukm = 0;
		}
		return 1;

	case EVP_BIGN_PKEY_CTRL_SET_KDF_NUM:
		if ((dctx->flags & EVP_BIGN_PKEY_KDF_BAKE) == 0)
			return -2;
		dctx->kdf_num = (size_t)p1;
		return 1;

	case EVP_PKEY_CTRL_MD:
		md = (const EVP_MD*)p2;
		if (dctx->params_nid != NID_undef)
		{
			evpBign_nid2params(params, dctx->params_nid);
			// нарушена совместимость с params_nid?
			if ((int)params->l != EVP_MD_meth_get_result_size(md) * 4)
				return 0;
		}
		dctx->md = md;
		return 1;

	case EVP_PKEY_CTRL_GET_MD:
		*(const EVP_MD**)p2 = dctx->md;
		return 1;

	// также поддерживаются
	case EVP_PKEY_CTRL_PEER_KEY:
	case EVP_PKEY_CTRL_DIGESTINIT:
	case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
	case EVP_PKEY_CTRL_PKCS7_DECRYPT:
	case EVP_PKEY_CTRL_PKCS7_SIGN:
	case EVP_PKEY_CTRL_CMS_DECRYPT:
	case EVP_PKEY_CTRL_CMS_ENCRYPT:
	case EVP_PKEY_CTRL_CMS_SIGN:
		return 1;

	default:
		return -2;
	}
}

int evpBign_pkey_set_params(EVP_PKEY_CTX* ctx, int params_nid)
{
	return EVP_PKEY_CTX_ctrl(ctx, NID_bign_pubkey, 
		EVP_PKEY_OP_TYPE_GEN,
		EVP_BIGN_PKEY_CTRL_SET_PARAMS, params_nid, 0);
}

int evpBign_pkey_set_enc_flags(EVP_PKEY_CTX* ctx, u8 flags)
{
	return EVP_PKEY_CTX_ctrl(ctx, NID_bign_pubkey, 
		EVP_PKEY_OP_TYPE_GEN,
		EVP_BIGN_PKEY_CTRL_SET_ENC_FLAGS, (int)flags, 0);
}

int evpBign_pkey_clr_enc_flags(EVP_PKEY_CTX* ctx, u8 flags)
{
	return EVP_PKEY_CTX_ctrl(ctx, NID_bign_pubkey, 
		EVP_PKEY_OP_TYPE_GEN,
		EVP_BIGN_PKEY_CTRL_CLR_ENC_FLAGS, (int)flags, 0);
}

int evpBign_pkey_set_sig_flags(EVP_PKEY_CTX* ctx, u8 flags)
{
	return EVP_PKEY_CTX_ctrl(ctx, NID_bign_pubkey,
		EVP_PKEY_OP_TYPE_SIG,
		EVP_BIGN_PKEY_CTRL_SET_ENC_FLAGS, (int)flags, 0);
}

int evpBign_pkey_clr_sig_flags(EVP_PKEY_CTX* ctx, u8 flags)
{
	return EVP_PKEY_CTX_ctrl(ctx, NID_bign_pubkey,
		EVP_PKEY_OP_TYPE_SIG,
		EVP_BIGN_PKEY_CTRL_CLR_ENC_FLAGS, (int)flags, 0);
}

int evpBign_pkey_set_kdf_flags(EVP_PKEY_CTX* ctx, u8 flags)
{
	return EVP_PKEY_CTX_ctrl(ctx, NID_bign_pubkey,
		EVP_PKEY_OP_DERIVE,
		EVP_BIGN_PKEY_CTRL_SET_ENC_FLAGS, (int)flags, 0);
}

int evpBign_pkey_clr_kdf_flags(EVP_PKEY_CTX* ctx, u8 flags)
{
	return EVP_PKEY_CTX_ctrl(ctx, NID_bign_pubkey,
		EVP_PKEY_OP_DERIVE,
		EVP_BIGN_PKEY_CTRL_CLR_ENC_FLAGS, (int)flags, 0);
}

int evpBign_pkey_set_kdf_ukm(EVP_PKEY_CTX* ctx, void* ukm,
	size_t ukm_len)
{
	return EVP_PKEY_CTX_ctrl(ctx, NID_bign_pubkey, 
		EVP_PKEY_OP_DERIVE,
		EVP_BIGN_PKEY_CTRL_SET_KDF_UKM, (int)ukm_len, ukm);
}

int evpBign_pkey_set_kdf_num(EVP_PKEY_CTX* ctx, size_t num)
{
	return EVP_PKEY_CTX_ctrl(ctx, NID_bign_pubkey, 
		EVP_PKEY_OP_DERIVE,
		EVP_BIGN_PKEY_CTRL_SET_KDF_NUM, (int)num, 0);
}

/*
*******************************************************************************
Строковая сtrl-функция
*******************************************************************************
*/
			
static int evpBign_pkey_ctrl_str(EVP_PKEY_CTX* ctx, const char* type, 
	const char* value)
{
	// долговременные параметры
	if (strEq(type, "params"))
	{
		int nid;
		nid = OBJ_sn2nid(value);
		if (nid == NID_undef)
			nid = OBJ_ln2nid(value);
		if (nid == NID_undef)
			return 0;
		return evpBign_pkey_set_params(ctx, nid);
	}
	// опции кодирования параметров
	if (strEq(type, "enc_params"))
	{
		if (strEq(value, "specified"))
			return evpBign_pkey_set_enc_flags(ctx, 
				EVP_BIGN_PKEY_ENC_PARAMS_SPECIFIED);
		if (strEq(value, "cofactor"))
			return evpBign_pkey_set_enc_flags(ctx, 
				EVP_BIGN_PKEY_ENC_PARAMS_COFACTOR);
		return -2;
	}
	// опции ЭЦП
	if (strEq(type, "sig"))
	{
		if (strEq(value, "deterministic"))
			return evpBign_pkey_set_sig_flags(ctx,
				EVP_BIGN_PKEY_SIG_DETERMINISTIC);
		return -2;
	}
	// опции kdf
	if (strEq(type, "kdf"))
	{
		if (strEq(value, "bake"))
			return evpBign_pkey_set_kdf_flags(ctx, EVP_BIGN_PKEY_KDF_BAKE);
		return -2;
	}
	return -2;
}

/*
*******************************************************************************
Описание методов ключа
*******************************************************************************
*/

static EVP_PKEY_METHOD* EVP_bign_pmeth;

const EVP_PKEY_METHOD* evpBign_pmeth()
{
	return EVP_bign_pmeth;
}

/*
*******************************************************************************
Регистрация алгоритмов
*******************************************************************************
*/

static int bign_pmeth_nids[128];
static int bign_pmeth_count;

#define BIGN_PMETH_REG(name, tmp)\
	(((tmp = NID_##name) != NID_undef) ?\
		bign_pmeth_nids[bign_pmeth_count++] = tmp :\
		(((tmp = OBJ_create(OID_##name, SN_##name, LN_##name)) > 0) ?\
			bign_pmeth_nids[bign_pmeth_count++] = tmp :	NID_undef))

/*
*******************************************************************************
Перечисление методов

\remark В prev_enum может задаваться указатель на перечислитель, объявленный 
в другом модуле. Тогда таблицы идентификаторов перечислителей объединяются.
*******************************************************************************
*/

static ENGINE_PKEY_METHS_PTR prev_enum;

static int evpBign_pmeth_enum(ENGINE* e, EVP_PKEY_METHOD** pmeth, 
	const int** nids, int nid)
{
	// возвратить таблицу идентификаторов?
	if (!pmeth)
	{
		// объединить таблицы?
		if (prev_enum && prev_enum != evpBign_pmeth_enum)
		{
			nid = prev_enum(e, pmeth, nids, nid);
			if (nid <= 0)
				return 0;
			if (bign_pmeth_count + nid >= (int)COUNT_OF(bign_pmeth_nids))
				return 0;
			memCopy(bign_pmeth_nids + bign_pmeth_count, *nids, 
				nid * sizeof(int));
			*nids = bign_pmeth_nids;
			return bign_pmeth_count + nid;
		}
		// нет, просто отчитаться за себя
		*nids = bign_pmeth_nids;
		return bign_pmeth_count;
	}
	// обработать запрос
	if (nid == NID_bign_pubkey)
		*pmeth = EVP_bign_pmeth;
	else if (prev_enum && prev_enum != evpBign_pmeth_enum)
		return prev_enum(e, pmeth, nids, nid);
	else
		return 0;
	// ответ найден
	return 1;
}

/*
*******************************************************************************
Подключение / закрытие

\warning Вызов EVP_PKEY_meth_free(EVP_bign_pmeth) в evpBign_pmeth_destroy()
отключен (по аналогии с belt_pmeth.c), хотя включение вызова не приводит 
к ошибке.
*******************************************************************************
*/

int evpBign_pmeth_bind(ENGINE* e)
{
	int tmp;
	// зарегистрировать объекты и получить nid'ы
	if (BIGN_PMETH_REG(bign_with_hspec, tmp) == NID_undef ||
		BIGN_PMETH_REG(bign_with_hbelt, tmp) == NID_undef ||
		BIGN_PMETH_REG(bign_with_bash256, tmp) == NID_undef ||
		BIGN_PMETH_REG(bign_with_bash384, tmp) == NID_undef ||
		BIGN_PMETH_REG(bign_with_bash512, tmp) == NID_undef ||
		BIGN_PMETH_REG(bign_keytransport, tmp) == NID_undef ||
		BIGN_PMETH_REG(bign_curve256v1, tmp) == NID_undef ||
		BIGN_PMETH_REG(bign_curve384v1, tmp) == NID_undef ||
		BIGN_PMETH_REG(bign_curve512v1, tmp) == NID_undef ||
		BIGN_PMETH_REG(bign_primefield, tmp) == NID_undef ||
		BIGN_PMETH_REG(bign_pubkey, tmp) == NID_undef)
		return 0;
	// создать описатель методов ключа
	EVP_bign_pmeth = EVP_PKEY_meth_new(NID_bign_pubkey, 0);
	if (!EVP_bign_pmeth)
		return 0;
	// настроить описатель
	EVP_PKEY_meth_set_init(EVP_bign_pmeth, evpBign_pkey_init);
	EVP_PKEY_meth_set_copy(EVP_bign_pmeth, evpBign_pkey_copy);
	EVP_PKEY_meth_set_cleanup(EVP_bign_pmeth, evpBign_pkey_cleanup);
	EVP_PKEY_meth_set_paramgen(EVP_bign_pmeth, 0, evpBign_pkey_paramgen);
	EVP_PKEY_meth_set_keygen(EVP_bign_pmeth, 0, evpBign_pkey_keygen);
	EVP_PKEY_meth_set_sign(EVP_bign_pmeth, 0, evpBign_pkey_sign);
	EVP_PKEY_meth_set_verify(EVP_bign_pmeth, 0, evpBign_pkey_verify);
	EVP_PKEY_meth_set_encrypt(EVP_bign_pmeth, 0, evpBign_pkey_encrypt);
	EVP_PKEY_meth_set_decrypt(EVP_bign_pmeth, 0, evpBign_pkey_decrypt);
	EVP_PKEY_meth_set_derive(EVP_bign_pmeth, 0, evpBign_pkey_kdf_derive);
	EVP_PKEY_meth_set_ctrl(EVP_bign_pmeth, evpBign_pkey_ctrl, 
		evpBign_pkey_ctrl_str);
	// задать перечислитель
	prev_enum = ENGINE_get_pkey_meths(e);
	if (!ENGINE_set_pkey_meths(e, evpBign_pmeth_enum))
	{
		EVP_PKEY_meth_free(EVP_bign_pmeth);
		return 0;
	}
	return 1;
}

void evpBign_pmeth_finish()
{
}
