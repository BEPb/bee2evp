/*
*******************************************************************************
\file bign_ameth.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Data formats for bign
\created 2014.10.14
\version 2022.06.16
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/cms.h>
#include <openssl/pkcs7.h>
#include <bee2/core/blob.h>
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
Форматы данных для алгоритмов bign

Форматы задаются как ASN.1 методы, через структуру EVP_PKEY_ASN1_METHOD.

\remark По мотивам схемы подключения EC (openssl/crypto/ec/ec_ameth.c).

\warning Не тестировались:
	evpBign_pkcs7_XXX.

\todo Поддержать методы siginf_set, sig_print [EVP_PKEY_ASN1_METHOD.pod]?

\todo Методы set_priv_key, get_priv_key используются в OpenSSL безопасно? 
*******************************************************************************
*/

static int evpBign_print_hex(BIO* bp, const void* buf, size_t len)
{
	const octet* tmp = (const octet*)buf;
	while (len--)
		if (BIO_printf(bp, "%02x", *tmp++) <= 0)
			return 0;
	return 1;
}

/*
*******************************************************************************
Параметры
*******************************************************************************
*/

static int evpBign_param_decode(EVP_PKEY* pkey, const octet** der, int der_len)
{
	bign_key* key;
	bool_t specified;
	key = (bign_key*)blobCreate(sizeof(bign_key));
	if (!key)
		return 0;
	if (!evpBign_asn1_d2i_params(key, &specified, der, der_len))
	{	
		blobClose(key);
		return 0;
	}
	EVP_PKEY_assign(pkey, NID_bign_pubkey, key);
	return 1;
}

static int evpBign_param_encode(const EVP_PKEY* pkey, octet** der)
{
	const bign_key* key = (const bign_key*)EVP_PKEY_get0(pkey);
	bool_t specified;
	return evpBign_asn1_i2d_params(der, &specified, key);
}

static int evpBign_param_missing(const EVP_PKEY* pkey)
{
	const bign_key* key = (const bign_key*)EVP_PKEY_get0(pkey);
	if (!key)
		return 1;
	ASSERT(memIsValid(key, sizeof(bign_key)));
	if (key->params->l != 128 && 
		key->params->l != 192 && 
		key->params->l != 256)
		return 1;
	return 0;
}

static int evpBign_param_copy(EVP_PKEY* to, const EVP_PKEY* from)
{
	const bign_key* keyfrom = (const bign_key*)EVP_PKEY_get0(from);
	bign_key* keyto = (bign_key*)EVP_PKEY_get0(to);
	if (!keyto)
	{
		if ((keyto = (bign_key*)blobCreate(sizeof(bign_key))) == 0)
			return 0;
		if (!EVP_PKEY_assign(to, NID_bign_pubkey, keyto))
		{
			blobClose(keyto);
			return 0;
		}
	}
	memCopy(keyto->params, keyfrom->params, sizeof(bign_params));
	return 1;
}

static int evpBign_param_cmp(const EVP_PKEY* a, const EVP_PKEY* b)
{
	const bign_key* keya = (const bign_key*)EVP_PKEY_get0(a);
	const bign_key* keyb = (const bign_key*)EVP_PKEY_get0(b);
	size_t len;
	// обработать уровень стойкости
	if (keya->params->l != keyb->params->l ||
		(keya->params->l != 128 && 
			keya->params->l != 192 && 
				keya->params->l != 256))
		return 0;
	len = 2 * O_OF_B(keya->params->l);
	// сравнить параметры
	return memEq(keya->params->p, keyb->params->p, len) &&
		memEq(keya->params->q, keyb->params->q, len) &&
		memEq(keya->params->a, keyb->params->a, len) &&
		memEq(keya->params->b, keyb->params->b, len) &&
		memEq(keya->params->yG, keyb->params->yG, len);
}

static int evpBign_param_print(BIO* bp, const EVP_PKEY* pkey, int indent,
	ASN1_PCTX *ctx)
{
	const bign_key* key;
	int nid;
	// загрузить key
	if (pkey == 0)
		return 0;
	key = (const bign_key*)EVP_PKEY_get0(pkey);
	// именованная кривая?
	nid = evpBign_params2nid(key->params);
	if (nid)
	{
		if (!BIO_indent(bp, indent, 128) ||
			BIO_printf(bp, "Std Params: %s\n", OBJ_nid2sn(nid)) <= 0)
			return 0;
	}
	else
	{
		size_t len = O_OF_B(key->params->l) * 2;
		if (len != 32 && len != 48 && len != 64 ||
			!BIO_indent(bp, indent, 128) ||
			BIO_printf(bp, "p:    ") <= 0 ||
			!evpBign_print_hex(bp, key->params->p, len) ||
			BIO_printf(bp, "\nq:    ") <= 0 || 
			!evpBign_print_hex(bp, key->params->q, len) ||
			BIO_printf(bp, "\na:    ") <= 0 || 
			!evpBign_print_hex(bp, key->params->a, len) ||
			BIO_printf(bp, "\nb:    ") <= 0 || 
			!evpBign_print_hex(bp, key->params->b, len) ||
			BIO_printf(bp, "\nyG:   ") <= 0 || 
			!evpBign_print_hex(bp, key->params->yG, len) ||
			BIO_printf(bp, "\nseed: ") <= 0 || 
			!evpBign_print_hex(bp, key->params->seed, 8))
			return 0;
	}
	return 1;
}

static int evpBign_param_check(const EVP_PKEY* pkey)
{
	const bign_key* key = (const bign_key*)EVP_PKEY_get0(pkey);
	return bignValParams(key->params) == ERR_OK;
}

/*
*******************************************************************************
Открытый ключ

Реализована поддержка следующей структуры ASN.1, описанной
в СТБ 34.101.45 [приложение Д]:

  SubjectPublicKeyInfo ::= SEQUENCE {
    algorithm AlgorithmIdentifier,
    subjectPublicKey PublicKey
  }

Этой структуре соответствует тип X509_PUBKEY.

\remark Поддержка PublicKey и структуры DomainParameters, вложенной в 
AlgorithmIdentifier, реализована в bign_asn1.c.
*******************************************************************************
*/

static int evpBign_pub_encode0(void** params, int* params_type, 
	const bign_key* key)
{
	bool_t specified;
	// кодировать явные параметры
	if (specified = key->flags & EVP_BIGN_PKEY_ENC_PARAMS_SPECIFIED)
	{
		octet* out = 0;
		int out_len;
		ASN1_STRING* str;
		// кодировать
		out_len = evpBign_asn1_i2d_params(&out, &specified, key);
		if (out_len <= 0 || !specified)
			return 0;
		str = ASN1_STRING_new();
		if (!str)
		{
			OPENSSL_free(out);
			return 0;
		}
		str->data = out;
		str->length = out_len;
		*params = str;
		*params_type = V_ASN1_SEQUENCE;
	}
	// кодировать именованные параметры
	else
	{
		ASN1_OBJECT* obj = OBJ_nid2obj(evpBign_params2nid(key->params));
		if (!obj)
			return 0;
		*params = obj;
		*params_type = V_ASN1_OBJECT;
	}
	return 1;
}

static int evpBign_pub_encode(X509_PUBKEY* pk, const EVP_PKEY* pkey)
{
	bign_key* key = (bign_key*)EVP_PKEY_get0(pkey);
	void* params = 0;
	int params_type = 0;
	octet* pubkey = 0;
	int pubkey_len;
	// кодировать параметры
	if (!evpBign_pub_encode0(&params, &params_type, key))
		goto err;
	// кодировать открытый ключ
	pubkey_len = evpBign_asn1_i2o_pubkey(&pubkey, key);
	if (pubkey_len <= 0)
		goto err;
	// кодировать SubjectPublicKeyInfo
	if (X509_PUBKEY_set0_param(pk, OBJ_nid2obj(NID_bign_pubkey),
			params_type, params, pubkey, pubkey_len))
		return 1;
err:
	if (params_type == V_ASN1_SEQUENCE)
		ASN1_STRING_free((ASN1_STRING*)params);
	else if (params_type == V_ASN1_OBJECT)
		ASN1_OBJECT_free((ASN1_OBJECT*)params);
	if (pubkey)
		OPENSSL_free(pubkey);
	return 0;
}

static int evpBign_pub_decode0(bign_key* key, int params_type, 
	const void* params)
{
	// параметры заданы явно?
	if (params_type == V_ASN1_SEQUENCE)
	{
		const ASN1_STRING* str = (const ASN1_STRING*)params;
		const octet* in = str->data;
		int in_len = str->length;
		bool_t specified;
		return evpBign_asn1_d2i_params(key, &specified, &in, in_len) &&
			specified;
	}
	// параметры заданы неявно?
	if (params_type == V_ASN1_OBJECT)
	{
		int nid = OBJ_obj2nid((const ASN1_OBJECT*)params);
		return evpBign_nid2params(key->params, nid);
	}
	return 0;
}

static int evpBign_pub_decode(EVP_PKEY* pkey, X509_PUBKEY* pk)
{
	const octet* pubkey;
	int pubkey_len;
	const void* params;
	X509_ALGOR* palg;
	int params_type;
	bign_key* key;
	// разобрать SubjectPublicKeyInfo
	if (!X509_PUBKEY_get0_param(0, &pubkey, &pubkey_len, &palg, pk))
		return 0;
	X509_ALGOR_get0(0, &params_type, &params, palg);
	// создать открытый ключ
	key = (bign_key*)blobCreate(sizeof(bign_key));
	if (!key)
		return 0;
	// декодировать параметры открытого ключа
	if (!evpBign_pub_decode0(key, params_type, params))
		goto err;
	// декодировать открытый ключ
	if (!evpBign_asn1_o2i_pubkey(key, &pubkey, pubkey_len))
		goto err;
	// зафиксировать key
	EVP_PKEY_assign(pkey, NID_bign_pubkey, key);
	return 1;
err:
	if (key)
		blobClose(key);
	return 0;
}

static int evpBign_pub_cmp(const EVP_PKEY* a, const EVP_PKEY* b)
{
	const bign_key* keya = (const bign_key*)EVP_PKEY_get0(a);
	const bign_key* keyb = (const bign_key*)EVP_PKEY_get0(b);
	// параметры должны совпадать
	ASSERT(evpBign_param_cmp(a, b));
	// сравнить открытые ключи
	return memEq(keya->pubkey, keyb->pubkey, O_OF_B(keya->params->l) * 4);
}

static int evpBign_pub_print(BIO* bp, const EVP_PKEY* pkey, int indent,
	ASN1_PCTX* ctx)
{
	const bign_key* key = (const bign_key*)EVP_PKEY_get0(pkey);
	size_t len = O_OF_B(key->params->l) * 4;
	return BIO_indent(bp, indent, 128) &&
		BIO_printf(bp, "Pubkey:  ") > 0 &&
		evpBign_print_hex(bp, key->pubkey, len) &&
		BIO_printf(bp, "\n") > 0;
}

static int evpBign_pub_check(const EVP_PKEY* pkey)
{
	const bign_key* key = (const bign_key*)EVP_PKEY_get0(pkey);
	return bignValPubkey(key->params, key->pubkey) == ERR_OK;
}

/*
*******************************************************************************
Личный ключ

Личный ключ описывается следующей структурой, определенной в PKCS#8 
и поддержанной типом PKCS8_PRIV_KEY_INFO:

PrivateKeyInfo ::= SEQUENCE {
   version INTEGER,
   privateKeyAlgorithm AlgorithmIdentifier,
   privateKey OCTET STRING,
   attributes [0] Attributes OPTIONAL 
}

Тип профилируется в СТБ 34.101.bpki следующим образом:
1) version = 0;
2) privateKeyAlgorithm = {bign-pubkey, (bign_curve256v1 | ...)};
3) privateKey содержит личный ключ;
4) список attributes пустой.

\remark Реализация разрешает указывать ЭК в параметрах privateKeyAlgorithm 
не только в форме named, но еще и в форме specified.

\warning В evpBign_priv_decode() для передачи лк в PKCS8_pkey_set0() 
приходится помещать его в обычный блок памяти (а не в блоб).
*******************************************************************************
*/

static int evpBign_priv_decode(EVP_PKEY* pkey, const PKCS8_PRIV_KEY_INFO* p8)
{
	const octet* privkey;
	int privkey_len;
	const void* params;
	const X509_ALGOR* palg;
	int params_type;
	bign_key* key;
	// разобрать PrivateKeyInfo
	if (!PKCS8_pkey_get0(0, &privkey, &privkey_len, &palg, p8))
		return 0;
	X509_ALGOR_get0(0, &params_type, &params, palg);
	// создать ключ
	key = (bign_key*)blobCreate(sizeof(bign_key));
	if (!key)
		return 0;
	// декодировать параметры открытого ключа
	if (!evpBign_pub_decode0(key, params_type, params))
		goto err;
	// проверить длину личного ключа
	if (privkey_len * 4 != (int)key->params->l)
		goto err;
	// сохранить личный ключ
	memCopy(key->privkey, privkey, privkey_len);
	// вычислить открытый ключ
	if (bignCalcPubkey(key->pubkey, key->params, key->privkey) != ERR_OK)
		goto err;
	// зафиксировать key
	EVP_PKEY_assign(pkey, NID_bign_pubkey, key);
	return 1;
err:
	if (key)
		blobClose(key);
	return 0;
}

static int evpBign_priv_encode(PKCS8_PRIV_KEY_INFO* p8, const EVP_PKEY* pkey)
{
	bign_key* key = (bign_key*)EVP_PKEY_get0(pkey);
	void* params = 0;
	int params_type = 0;
	octet* privkey = 0;
	// кодировать параметры
	if (!evpBign_pub_encode0(&params, &params_type, key))
		goto err;
	// кодировать личный ключ
	privkey = (octet*)OPENSSL_malloc(key->params->l / 4);
	if (privkey == 0)
		goto err;
	memCopy(privkey, key->privkey, key->params->l / 4);
	// кодировать PrivateKeyInfo
	if (PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_bign_pubkey), 0,
		params_type, params, privkey, key->params->l / 4))
		return 1;
err:
	if (params_type == V_ASN1_SEQUENCE)
		ASN1_STRING_free((ASN1_STRING*)params);
	else if (params_type == V_ASN1_OBJECT)
		ASN1_OBJECT_free((ASN1_OBJECT*)params);
	if (privkey)
		OPENSSL_free(privkey);
	return 0;
}

static int evpBign_priv_print(BIO* bp, const EVP_PKEY* pkey, int indent,
	ASN1_PCTX* ctx)
{
	const bign_key* key = (const bign_key*)EVP_PKEY_get0(pkey);
	size_t len = O_OF_B(key->params->l) * 2;
	return BIO_indent(bp, indent, 128) &&
		BIO_printf(bp, "Privkey: ") > 0 &&
		evpBign_print_hex(bp, key->privkey, len) &&
		BIO_printf(bp, "\n") > 0;
}

static int evpBign_keypair_check(const EVP_PKEY* pkey)
{
	const bign_key* key = (const bign_key*)EVP_PKEY_get0(pkey);
	return bignValKeypair(key->params, key->privkey, key->pubkey) == ERR_OK;
}

/*
*******************************************************************************
Размерности
*******************************************************************************
*/

static int evpBign_pkey_size(const EVP_PKEY* pkey)
{
	const bign_key* key = (const bign_key*)EVP_PKEY_get0(pkey);
	return (int)(O_OF_B(key->params->l) * 3);
}

static int evpBign_pkey_bits(const EVP_PKEY* pkey)
{
	const bign_key* key = (const bign_key*)EVP_PKEY_get0(pkey);
	return (int)(key->params->l * 2);
}

static int evpBign_pkey_security_bits(const EVP_PKEY* pkey)
{
	const bign_key* key = (const bign_key*)EVP_PKEY_get0(pkey);
	return (int)(key->params->l);
}

/*
*******************************************************************************
Очистка
*******************************************************************************
*/

static void evpBign_pkey_free(EVP_PKEY* pkey)
{
	blobClose(EVP_PKEY_get0(pkey));
}

/*
*******************************************************************************
CMS: подпись

Функция evpBign_cms_sign(), evpBign_cms_verify() обрабатывают структуру 
SignerInfo при выработке и проверке подписи. 

Структура SignerInfo описывается следующим образом:
	SignerInfo ::= SEQUENCE {
		version CMSVersion,
		sid SignerIdentifier,
		digestAlgorithm AlgorithmIdentifier,
		signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
		signatureAlgorithm AlgorithmIdentifier,
		signature SignatureValue,
		unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL}.
(устройство компонент подробно описано в СТБ 34.101.23).

Требования СТБ 34.101.45 (Д.2):

1. Если signatureAlgorithm.algorithm == bign_with_hbelt, то 
параметры signatureAlgorithm.parameters описываются типом NULL. 

2. Если signatureAlgorithm.algorithm == bign_with_hspec, то в 
signatureAlgorithm.parameters должен задаваться идентификатор используемой
функции хэширования и этот идентификатор должен совпадать 
с digestAlgorithm.algorithm.

Дополнительное требование:

3. Если signatureAlgorithm.algorithm == bign_with_bashXXX, то 
параметры signatureAlgorithm.parameters описываются типом NULL. 
*******************************************************************************
*/

static int evpBign_cms_sign(CMS_SignerInfo* si)
{
	int hnid;
	X509_ALGOR* alg1;
	X509_ALGOR* alg2;
	// загрузить алгоритмы
	CMS_SignerInfo_get0_algs(si, 0, 0, &alg1, &alg2);
	if (alg1 == 0 || alg1->algorithm == 0)
		return 0;
	// hnid -> snid \in {bign_with_hbelt, bign_with_bashXXX}
	hnid = OBJ_obj2nid(alg1->algorithm);
	if (hnid == NID_belt_hash)
		return X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_bign_with_hbelt), 
			V_ASN1_NULL, 0);
	if (hnid == NID_bash256)
		return X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_bign_with_bash256), 
			V_ASN1_NULL, 0);
	if (hnid == NID_bash384)
		return X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_bign_with_bash384), 
			V_ASN1_NULL, 0);
	if (hnid == NID_bash512)
		return X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_bign_with_bash512), 
			V_ASN1_NULL, 0);
	// hnid -> bign_with_hspec
	return X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_bign_with_hspec), 
		V_ASN1_OBJECT, OBJ_dup(alg1->algorithm));
}

static int evpBign_cms_verify(CMS_SignerInfo* si)
{
	int hnid;
	int snid;
	X509_ALGOR* alg1;
	X509_ALGOR* alg2;
	// загрузить алгоритмы
	CMS_SignerInfo_get0_algs(si, 0, 0, &alg1, &alg2);
	if (alg1 == 0 || alg1->algorithm == 0 || alg2 == 0 || alg2->algorithm == 0)
		return 0;
	// определить идентификаторы алгоритмов
	hnid = OBJ_obj2nid(alg1->algorithm);
	snid = OBJ_obj2nid(alg2->algorithm);
	// snid \in {bign_with_hbelt, bign_with_bashXXX}?
	if (snid == NID_bign_with_hbelt)
		return hnid == NID_belt_hash && alg2->parameter->type == V_ASN1_NULL;
	if (snid == NID_bign_with_bash256)
		return hnid == NID_bash256 && alg2->parameter->type == V_ASN1_NULL;
	if (snid == NID_bign_with_bash384)
		return hnid == NID_bash384 && alg2->parameter->type == V_ASN1_NULL;
	if (snid == NID_bign_with_bash512)
		return hnid == NID_bash512 && alg2->parameter->type == V_ASN1_NULL;
	// snid == bign_with_hspec?
	if (snid == NID_bign_with_hspec)
		return alg2->parameter->type == V_ASN1_OBJECT &&
			hnid != NID_undef &&
			hnid == OBJ_obj2nid(alg2->parameter->value.object);
	// нестандартный идентификатор алгоритма ЭЦП?
	return 0;
}

/*
*******************************************************************************
PKCS7: подпись

todo: разобраться до конца (упрощение CMS?)
*******************************************************************************
*/

static int evpBign_pkcs7_sign(PKCS7_SIGNER_INFO* si)
{
	int hnid;
	X509_ALGOR* alg1;
	X509_ALGOR* alg2;
	// загрузить алгоритмы
	PKCS7_SIGNER_INFO_get0_algs(si, 0, &alg1, &alg2);
	if (alg1 == 0 || alg1->algorithm == 0)
		return 0;
	// hnid -> snid \in {bign_with_hbelt, bign_with_bashXXX}
	hnid = OBJ_obj2nid(alg1->algorithm);
	if (hnid == NID_belt_hash)
		return X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_bign_with_hbelt), 
			V_ASN1_NULL, 0);
	if (hnid == NID_bash256)
		return X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_bign_with_bash256), 
			V_ASN1_NULL, 0);
	if (hnid == NID_bash384)
		return X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_bign_with_bash384), 
			V_ASN1_NULL, 0);
	if (hnid == NID_bash512)
		return X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_bign_with_bash512), 
			V_ASN1_NULL, 0);
	// hnid -> bign_with_hspec
	return X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_bign_with_hspec), 
		V_ASN1_OBJECT, OBJ_dup(alg1->algorithm));
}

static int evpBign_pkcs7_verify(PKCS7_SIGNER_INFO* si)
{
	int hnid;
	int snid;
	X509_ALGOR* alg1;
	X509_ALGOR* alg2;
	// загрузить алгоритмы
	PKCS7_SIGNER_INFO_get0_algs(si, 0, &alg1, &alg2);
	if (alg1 == 0 || alg1->algorithm == 0 || alg2 == 0 || alg2->algorithm == 0)
		return 0;
	// определить идентификаторы алгоритмов
	hnid = OBJ_obj2nid(alg1->algorithm);
	snid = OBJ_obj2nid(alg2->algorithm);
	// snid \in {bign_with_hbelt, bign_with_bashXXX}?
	if (snid == NID_bign_with_hbelt)
		return hnid == NID_belt_hash && alg2->parameter->type == V_ASN1_NULL;
	if (snid == NID_bign_with_bash256)
		return hnid == NID_bash256 && alg2->parameter->type == V_ASN1_NULL;
	if (snid == NID_bign_with_bash384)
		return hnid == NID_bash384 && alg2->parameter->type == V_ASN1_NULL;
	if (snid == NID_bign_with_bash512)
		return hnid == NID_bash512 && alg2->parameter->type == V_ASN1_NULL;
	// snid == bign_with_hspec?
	if (snid == NID_bign_with_hspec)
		return alg2->parameter->type == V_ASN1_OBJECT &&
			hnid != NID_undef &&
			hnid == OBJ_obj2nid(alg2->parameter->value.object);
	// нестандартный идентификатор алгоритма ЭЦП?
	return 0;
}

/*
*******************************************************************************
CMS: конвертование (шифрование)

При шифровании данных ключевой материал передается в структуре 
	RecipientInfo ::= CHOICE {
		ktri KeyTransRecipientInfo,
		kari [1] KeyAgreeRecipientInfo,
		kekri [2] KEKRecipientInfo,
		pwri [3] PasswordRecipientinfo,
		ori [4] OtherRecipientInfo}
(см. СТБ 34.101.23).

Поддерживается только компонент KeyTransRecipientInfo, который описывается
следующим образом:
	KeyTransRecipientInfo ::= SEQUENCE {
		version CMSVersion,
		rid RecipientIdentifier,
		keyEncryptionAlgorithm AlgorithmIdentifier,
		encryptedKey EncryptedKey}

Требования СТБ 34.101.23 (Б.4): 
1. В keyEncryptionAlgorithm.algorithm задается идентификатор 
bign_keytransport. 

2. Параметры keyEncryptionAlgorithm.parameters опускаются. 
*******************************************************************************
*/

static int evpBign_cms_encrypt(CMS_RecipientInfo* ri)
{
	X509_ALGOR* alg;
	if (!CMS_RecipientInfo_ktri_get0_algs(ri, 0, 0, &alg))
		return 0;
	return X509_ALGOR_set0(alg, OBJ_nid2obj(NID_bign_keytransport), 
		V_ASN1_NULL, 0);
}

static int evpBign_cms_decrypt(CMS_RecipientInfo* ri)
{
	X509_ALGOR* alg;
	if (!CMS_RecipientInfo_ktri_get0_algs(ri, 0, 0, &alg))
		return 0;
	return OBJ_obj2nid(alg->algorithm) == NID_bign_keytransport &&
		alg->parameter->type == V_ASN1_NULL;
}

/*
*******************************************************************************
PKCS7: конвертование (шифрование)

todo: разобраться до конца (упрощение CMS?)
*******************************************************************************
*/

static int evpBign_pkcs7_decrypt(PKCS7_RECIP_INFO* ri)
{
	X509_ALGOR* alg;
	PKCS7_RECIP_INFO_get0_alg(ri, &alg);
	return OBJ_obj2nid(alg->algorithm) == NID_bign_keytransport &&
		alg->parameter->type == V_ASN1_NULL;
}

static int evpBign_pkcs7_encrypt(PKCS7_RECIP_INFO* ri)
{
	X509_ALGOR* alg;
	PKCS7_RECIP_INFO_get0_alg(ri, &alg);
	return X509_ALGOR_set0(alg, OBJ_nid2obj(NID_bign_keytransport), 
		V_ASN1_NULL, 0);
}

/*
*******************************************************************************
Управление
*******************************************************************************
*/

static int evpBign_pkey_asn1_ctrl(EVP_PKEY* pkey, int op, long arg1, void* arg2)
{
	bign_key* key;
	switch (op)
	{
	case ASN1_PKEY_CTRL_PKCS7_SIGN:
		if (arg1 == 0)
			return evpBign_pkcs7_sign((PKCS7_SIGNER_INFO*)arg2);
		else if (arg1 == 1)
			return evpBign_pkcs7_verify((PKCS7_SIGNER_INFO*)arg2);
		return -2;

	case ASN1_PKEY_CTRL_CMS_SIGN:
		if (arg1 == 0)
			return evpBign_cms_sign((CMS_SignerInfo*)arg2);
		else if (arg1 == 1)
			return evpBign_cms_verify((CMS_SignerInfo*)arg2);
		return -2;

	case ASN1_PKEY_CTRL_CMS_RI_TYPE:
		*(int*)arg2 = CMS_RECIPINFO_TRANS;
		return 1;

	case ASN1_PKEY_CTRL_PKCS7_ENCRYPT:
		if (arg1 == 0)
			return evpBign_pkcs7_encrypt((PKCS7_RECIP_INFO*)arg2);
		else if (arg1 == 1)
			return evpBign_pkcs7_decrypt((PKCS7_RECIP_INFO*)arg2);
		return -2;

	case ASN1_PKEY_CTRL_CMS_ENVELOPE:
		if (arg1 == 0)
			return evpBign_cms_encrypt((CMS_RecipientInfo*)arg2);
		else if (arg1 == 1)
			return evpBign_cms_decrypt((CMS_RecipientInfo*)arg2);
		return -2;

	case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
		if (!pkey)
		{
			*(int*)arg2 = NID_belt_hash;
			return 2;
		}
		else
		{
			// в соответствии со связками хэш + ЭЦП, заданными в bee2evp_bind()
			key = (bign_key*)EVP_PKEY_get0(pkey);
			if (key->hash_nid != NID_undef)
				*(int*)arg2 = key->hash_nid;
			else if (key->params->l == 128)
				*(int*)arg2 = NID_belt_hash;
			else if (key->params->l == 192)
				*(int*)arg2 = NID_bash384;
			else if (key->params->l == 256)
				*(int*)arg2 = NID_bash512;
			else
				return -1;
			return 2;
		}

	case ASN1_PKEY_CTRL_SET1_TLS_ENCPT:
		key = (bign_key*)EVP_PKEY_get0(pkey);
		ASSERT(memIsValid(key, sizeof(bign_key)));
		if (arg1 != key->params->l / 2)
			return 0;
		memCopy(key->pubkey, arg2, arg1);
		return 1;

	case ASN1_PKEY_CTRL_GET1_TLS_ENCPT:
		key = (bign_key*)EVP_PKEY_get0(pkey);
		ASSERT(memIsValid(key, sizeof(bign_key)));
		if (!EVP_PKEY_missing_parameters(pkey))
		{
			octet** pt = arg2;
			if (*pt = OPENSSL_memdup(key->pubkey, key->params->l / 2))
				return key->params->l / 2;
		}
		return 0;

	default:
		return -2;
	}
}

/*
*******************************************************************************
Параметры алгоритмов ЭЦП

Функция v() интерфейса EVP_PKEY_ASN1_METHOD::item_verify() вызывается только 
в функции ASN1_item_verify() (модуль a_verify.c). В последней функции 
по идентификатору алгоритма ЭЦП (snid) определяется сопутствующий 
алгоритм хэширования (hnid). Если hnid по snid определить не удалось, 
то вызывается v(). Если удалось, то инициализируется проверка подписи. 

Функция s() интерфейса EVP_PKEY_ASN1_METHOD::item_sign() вызывается только 
в функции ASN1_item_sign_ctx() (модуль a_sign.c). В последней функции s()
вызывается безусловно. В s() можно настроить параметры алгоритма ЭЦП. 

В функции evpBign_item_verify(), реализующей интерфейс item_verify(), по snid
определяется hnid, а затем инициализируется проверка подписи.

В функции evpBign_item_sign(), реализующей интерфейс item_sign(), по hnid
определяется snid, а затем настраиваются параметры подписи.

\remark Информация об интерфейсе EVP_PKEY_ASN1_METHOD::item_verify() 
из модуля a_verify.c:
	Return value of 2 means carry on, anything else means we
	exit straight away: either a fatal error of the underlying
	verification routine handles all verification.

\remark Информация об интерфейсе EVP_PKEY_ASN1_METHOD::item_sign() 
из модуля a_sign.c:
	Return value meanings:
	 <= 0: error.
	  1: method does everything.
	  2: carry on as normal.
	  3: ASN1 method sets algorithm identifiers: just sign.
*******************************************************************************
*/

int evpBign_item_verify(EVP_MD_CTX* ctx, const ASN1_ITEM* it, void* asn,
	X509_ALGOR* alg, ASN1_BIT_STRING* sig, EVP_PKEY* pkey)
{
	const ASN1_OBJECT* sobj;
	int snid;
	const void* params;
	int params_type;
	const EVP_MD* md;
	// получить snid и параметры
	X509_ALGOR_get0(&sobj, &params_type, &params, alg);
	snid = OBJ_obj2nid(sobj);
	if (snid == 0)
		return 0;
	// snid -> md
	if (snid == NID_bign_with_hbelt)
	{
		if (params_type != V_ASN1_NULL)
			return 0;
		md = EVP_get_digestbynid(NID_belt_hash);
	}
	else if (snid == NID_bign_with_bash256)
	{
		if (params_type != V_ASN1_NULL)
			return 0;
		md = EVP_get_digestbynid(NID_bash256);
	}
	else if (snid == NID_bign_with_bash384)
	{
		if (params_type != V_ASN1_NULL)
			return 0;
		md = EVP_get_digestbynid(NID_bash384);
	}
	else if (snid == NID_bign_with_bash512)
	{
		if (params_type != V_ASN1_NULL)
			return 0;
		md = EVP_get_digestbynid(NID_bash512);
	}
	else if (snid == NID_bign_with_hspec)
	{
		if (params_type != V_ASN1_OBJECT)
			return 0;
		md = EVP_get_digestbynid(OBJ_obj2nid((ASN1_OBJECT*)params));
	}
	// snid не поддерживается
	else
		return 0;
	// начать проверку ЭЦП
	if (md == 0 || !EVP_DigestVerifyInit(ctx, 0, md, 0, pkey))
		return 0;
	// все нормально
	return 2;
}

int evpBign_item_sign(EVP_MD_CTX* ctx, const ASN1_ITEM* it, void* asn,
	X509_ALGOR* alg1, X509_ALGOR* alg2, ASN1_BIT_STRING* sig)
{
	int hnid = EVP_MD_type(EVP_MD_CTX_md(ctx));
	int snid = 0;
	void* params;
	int params_type;
	// hnid -> snid
	if (hnid == NID_belt_hash)
		snid = NID_bign_with_hbelt;
	else if (hnid == NID_bash256)
		snid = NID_bign_with_bash256;
	else if (hnid == NID_bash384)
		snid = NID_bign_with_bash384;
	else if (hnid == NID_bash512)
		snid = NID_bign_with_bash512;
	else
		snid = NID_bign_with_hspec;
	// хэш-алгоритм не поддерживается?
	if (snid == NID_undef)
		return 0;
	// snid == bign_with_hbelt or bign_with_bashXXX => params <- NULL
	if (snid == NID_bign_with_hbelt ||
		snid == NID_bign_with_bash256 ||
		snid == NID_bign_with_bash384 ||
		snid == NID_bign_with_bash512)
	{
		params_type = V_ASN1_NULL;
		params = 0;
	}
	// snid == bign_with_hspec => params <- OID(hash)
	else
	{
		params_type = V_ASN1_OBJECT;
		params = OBJ_nid2obj(hnid);
	}
	// установить snid и параметры
	if (alg1 && !X509_ALGOR_set0(alg1, OBJ_nid2obj(snid), params_type, params))
		return 0;
	if (alg2 && !X509_ALGOR_set0(alg2, OBJ_nid2obj(snid), params_type, params))
		return 0;
	// все нормально
	return 3;
}

/*
*******************************************************************************
Открытый ключ как строка октетов
*******************************************************************************
*/

static int evpBign_set_pubkey(EVP_PKEY* pkey, const octet* pubkey,
	size_t len)
{
	bign_key* key;
	if (evpBign_param_missing(pkey))
		return 0;
	key = (bign_key*)EVP_PKEY_get0(pkey);
	if (len != key->params->l / 2)
		return 0;
	memCopy(key->pubkey, pubkey, len);
	return 1;
}

static int evpBign_get_pubkey(const EVP_PKEY* pkey, octet* pubkey,
	size_t* len)
{
	const bign_key* key;
	if (evpBign_param_missing(pkey))
		return 0;
	key = (const bign_key*)EVP_PKEY_get0(pkey);
	if (pubkey == 0)
	{
		*len = key->params->l / 2;
		return 1;
	}
	if (*len < key->params->l / 2)
		return 0;
	memCopy(pubkey, key->pubkey, *len = key->params->l / 2);
	return 1;
}


/*
*******************************************************************************
Личный ключ как строка октетов
*******************************************************************************
*/

static int evpBign_set_privkey(EVP_PKEY *pkey, const octet* privkey,
	size_t len)
{
	bign_key* key;
	if (evpBign_param_missing(pkey))
		return 0;
	key = (bign_key*)EVP_PKEY_get0(pkey);
	if (len != key->params->l / 4)
		return 0;
	if (bignCalcPubkey(key->pubkey, key->params, privkey) != ERR_OK)
		return 0;
	memCopy(key->privkey, privkey, len);
	return 1;
}

static int evpBign_get_privkey(const EVP_PKEY* pkey, octet* privkey,
	size_t* len)
{
	const bign_key* key;
	if (evpBign_param_missing(pkey))
		return 0;
	key = (const bign_key*)EVP_PKEY_get0(pkey);
	if (privkey == 0)
	{
		*len = key->params->l / 4;
		return 1;
	}
	if (*len < key->params->l / 4)
		return 0;
	memCopy(privkey, key->privkey, *len = key->params->l / 4);
	return 1;
}

/*
*******************************************************************************
Описание форматов данных
*******************************************************************************
*/

static EVP_PKEY_ASN1_METHOD* EVP_bign_ameth;

const EVP_PKEY_ASN1_METHOD* evpBign_ameth()
{
	return EVP_bign_ameth;
}

/*
*******************************************************************************
Регистрация алгоритмов
*******************************************************************************
*/

static int bign_ameth_nids[128];
static int bign_ameth_count;

#define BIGN_AMETH_REG(name, tmp)\
	(((tmp = NID_##name) != NID_undef) ?\
		bign_ameth_nids[bign_ameth_count++] = tmp :\
		(((tmp = OBJ_create(OID_##name, SN_##name, LN_##name)) > 0) ?\
			bign_ameth_nids[bign_ameth_count++] = tmp : NID_undef))

/*
*******************************************************************************
Перечисление алгоритмов

\remark В prev_enum может задаваться указатель на перечислитель, объявленный 
в другом модуле. Тогда таблицы идентификаторов перечислителей объединяются.
*******************************************************************************
*/

static ENGINE_PKEY_ASN1_METHS_PTR prev_enum;

static int evpBign_ameth_enum(ENGINE* e, EVP_PKEY_ASN1_METHOD** ameth, 
	const int** nids, int nid)
{
	// возвратить таблицу идентификаторов?
	if (!ameth)
	{
		// объединить таблицы?
		if (prev_enum && prev_enum != evpBign_ameth_enum)
		{
			nid = prev_enum(e, ameth, nids, nid);
			if (nid <= 0)
				return 0;
			if (bign_ameth_count + nid >= (int)COUNT_OF(bign_ameth_nids))
				return 0;
			memCopy(bign_ameth_nids + bign_ameth_count, *nids, 
				nid * sizeof(int));
			*nids = bign_ameth_nids;
			return bign_ameth_count + nid;
		}
		// нет, просто отчитаться за себя
		*nids = bign_ameth_nids;
		return bign_ameth_count;
	}
	// обработать запрос
	if (nid == NID_bign_pubkey)
		*ameth = EVP_bign_ameth;
	else if (prev_enum && prev_enum != evpBign_ameth_enum)
		return prev_enum(e, ameth, nids, nid);
	else
		return 0;
	// ответ найден
	return 1;
}

/*
*******************************************************************************
Связывание
*******************************************************************************
*/

int evpBign_ameth_bind(ENGINE* e)
{
	int tmp;
	// зарегистрировать алгоритмы и получить nid'ы
	if (BIGN_AMETH_REG(bign_pubkey, tmp) == NID_undef)
		return 0;
	// создать описатель методов ключа
	EVP_bign_ameth = EVP_PKEY_asn1_new(NID_bign_pubkey, 0, "bign", 
		"OpenSSL bign method");
	if (!EVP_bign_ameth)
		return 0;
	// настроить описатель
	EVP_PKEY_asn1_set_param(EVP_bign_ameth,
		evpBign_param_decode,
		evpBign_param_encode,
		evpBign_param_missing,
		evpBign_param_copy,
		evpBign_param_cmp,
		evpBign_param_print);
	EVP_PKEY_asn1_set_param_check(EVP_bign_ameth,
		evpBign_param_check);
	EVP_PKEY_asn1_set_public(EVP_bign_ameth,
		evpBign_pub_decode,
		evpBign_pub_encode,
		evpBign_pub_cmp,
		evpBign_pub_print,
		evpBign_pkey_size,
		evpBign_pkey_bits);
	EVP_PKEY_asn1_set_public_check(EVP_bign_ameth,
		evpBign_pub_check);
	EVP_PKEY_asn1_set_private(EVP_bign_ameth,
		evpBign_priv_decode,
		evpBign_priv_encode,
		evpBign_priv_print);
	EVP_PKEY_asn1_set_check(EVP_bign_ameth,
		evpBign_keypair_check);
	EVP_PKEY_asn1_set_free(EVP_bign_ameth,
		evpBign_pkey_free);
	EVP_PKEY_asn1_set_ctrl(EVP_bign_ameth,
		evpBign_pkey_asn1_ctrl);
	EVP_PKEY_asn1_set_item(EVP_bign_ameth, 
		evpBign_item_verify, 
		evpBign_item_sign);
	EVP_PKEY_asn1_set_security_bits(EVP_bign_ameth,
		evpBign_pkey_security_bits);
	EVP_PKEY_asn1_set_set_pub_key(EVP_bign_ameth,
		evpBign_set_pubkey);
	EVP_PKEY_asn1_set_get_pub_key(EVP_bign_ameth,
		evpBign_get_pubkey);
	EVP_PKEY_asn1_set_set_priv_key(EVP_bign_ameth,
		evpBign_set_privkey);
	EVP_PKEY_asn1_set_get_priv_key(EVP_bign_ameth,
		evpBign_get_privkey);
	// задать перечислитель
	prev_enum = ENGINE_get_pkey_asn1_meths(e);
	if (!ENGINE_set_pkey_asn1_meths(e, evpBign_ameth_enum))
	{
		EVP_PKEY_asn1_free(EVP_bign_ameth);
		return 0;
	}
	return 1;
}

void evpBign_ameth_finish()
{
}
