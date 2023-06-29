/*
*******************************************************************************
\file bign_asn1.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief ASN1-structures for bign
\created 2013.11.01
\version 2017.09.21
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <bee2/core/blob.h>
#include <bee2/core/mem.h>
#include <bee2/crypto/bign.h>
#include "bee2evp/bee2evp.h"
#include "bee2evp_lcl.h"

/*
*******************************************************************************
Реализована поддержка следующих структур ASN.1, описанных 
в СТБ 34.101.45 [приложение Д]:

  DomainParameters ::= CHOICE {
    specified  ECParameters,
    named      OBJECT IDENTIFIER,
    implicit   NULL
  }

  ECParameters ::= SEQUENCE {
    version  INTEGER {ecpVer1(1)} (ecpVer1),
    fieldID  FieldID,
    curve    Curve,
    base     OCTET STRING (SIZE(32|48|64)),
    order    INTEGER,
    cofactor INTEGER (1) OPTIONAL
  }

  FieldID ::= SEQUENCE {
    fieldType   OBJECT IDENTIFIER (bign-primefield),
    parameters  INTEGER
  } 

  Curve ::= SEQUENCE {
    a     OCTET STRING (SIZE(32|48|64)),
    b     OCTET STRING (SIZE(32|48|64)),
    seed  BIT STRING (SIZE(64))
  }

  PublicKey ::= BIT STRING (SIZE(512|768|1024))
*******************************************************************************
*/

typedef struct
{
	ASN1_OBJECT* fieldType;
	ASN1_INTEGER* prime;
} BIGN_FIELDID;

typedef struct
{
	ASN1_OCTET_STRING* a;
	ASN1_OCTET_STRING* b;
	ASN1_BIT_STRING* seed;
} BIGN_CURVE;

typedef struct
{
	long version;
	BIGN_FIELDID* fieldID;
	BIGN_CURVE* curve;
	ASN1_OCTET_STRING* base;
	ASN1_INTEGER* order;
	ASN1_INTEGER* cofactor;
} BIGN_ECPARAMS;

typedef struct
{
	int	type;
	union {
		ASN1_OBJECT* named;
		BIGN_ECPARAMS* specified;
		ASN1_NULL* implicit;
	} value;
} BIGN_DOMAINPARAMS;

typedef struct 
{
	ASN1_OBJECT* algorithm;
	BIGN_DOMAINPARAMS* parameters;
} BIGN_ALGID;

typedef struct 
{
	long version;
	BIGN_ALGID* keyAlgorithm;
	ASN1_OCTET_STRING* privateKey;
} BIGN_PRIVATEKEY;

ASN1_SEQUENCE(BIGN_FIELDID) =
{
	ASN1_SIMPLE(BIGN_FIELDID, fieldType, ASN1_OBJECT),
	ASN1_SIMPLE(BIGN_FIELDID, prime, ASN1_INTEGER)
} ASN1_SEQUENCE_END(BIGN_FIELDID)

ASN1_SEQUENCE(BIGN_CURVE) = 
{
	ASN1_SIMPLE(BIGN_CURVE, a, ASN1_OCTET_STRING),
	ASN1_SIMPLE(BIGN_CURVE, b, ASN1_OCTET_STRING),
	ASN1_OPT(BIGN_CURVE, seed, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(BIGN_CURVE)

ASN1_SEQUENCE(BIGN_ECPARAMS) = 
{
	ASN1_SIMPLE(BIGN_ECPARAMS, version, LONG),
	ASN1_SIMPLE(BIGN_ECPARAMS, fieldID, BIGN_FIELDID),
	ASN1_SIMPLE(BIGN_ECPARAMS, curve, BIGN_CURVE),
	ASN1_SIMPLE(BIGN_ECPARAMS, base, ASN1_OCTET_STRING),
	ASN1_SIMPLE(BIGN_ECPARAMS, order, ASN1_INTEGER),
	ASN1_OPT(BIGN_ECPARAMS, cofactor, ASN1_INTEGER)
} ASN1_SEQUENCE_END(BIGN_ECPARAMS)

DECLARE_ASN1_ALLOC_FUNCTIONS(BIGN_ECPARAMS)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(BIGN_ECPARAMS)

ASN1_CHOICE(BIGN_DOMAINPARAMS) = 
{
	ASN1_SIMPLE(BIGN_DOMAINPARAMS, value.named, ASN1_OBJECT),
	ASN1_SIMPLE(BIGN_DOMAINPARAMS, value.specified, BIGN_ECPARAMS),
	ASN1_SIMPLE(BIGN_DOMAINPARAMS, value.implicit, ASN1_NULL)
} ASN1_CHOICE_END(BIGN_DOMAINPARAMS)

DECLARE_ASN1_FUNCTIONS_const(BIGN_DOMAINPARAMS)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(BIGN_DOMAINPARAMS, BIGN_DOMAINPARAMS)
IMPLEMENT_ASN1_FUNCTIONS_const(BIGN_DOMAINPARAMS)

/*
*******************************************************************************
Расширение модуля bee2/bign

\pre Параметры функции evpBign_eq_params() корректны. Поэтому можно сравнивать 
только тройки (p, a, b) [все остальные поля определяются по этой тройке].
*******************************************************************************
*/

int evpBign_eq_params(const bign_params* params1, const bign_params* params2)
{
	return params1 && params2 && 
		params1->l <= 256 && params1->l == params2->l &&
		memEq(params1->p, params2->p, params1->l / 4) &&
		memEq(params1->a, params2->a, params1->l / 4) &&
		memEq(params1->b, params2->b, params1->l / 4);
}

int evpBign_params2nid(const bign_params* params)
{
	bign_params std;

	if (!params)
		return 0;
	if (bignStdParams(&std, OID_bign_curve256v1) != ERR_OK)
		return 0;
	if (evpBign_eq_params(params, &std))
		return NID_bign_curve256v1;
	if (bignStdParams(&std, OID_bign_curve384v1) != ERR_OK)
		return 0;
	if (evpBign_eq_params(params, &std))
		return NID_bign_curve384v1;
	if (bignStdParams(&std, OID_bign_curve512v1) != ERR_OK)
		return 0;
	if (evpBign_eq_params(params, &std))
		return NID_bign_curve512v1;
	return 0;
}

int evpBign_nid2params(bign_params* params, int nid)
{
	if (nid == NID_bign_curve256v1)
		return bignStdParams(params, OID_bign_curve256v1) == ERR_OK;
	if (nid == NID_bign_curve384v1)
		return bignStdParams(params, OID_bign_curve384v1) == ERR_OK;
	if (nid == NID_bign_curve512v1)
		return bignStdParams(params, OID_bign_curve512v1) == ERR_OK;
	return 0;
}

/*
*******************************************************************************
Запись параметров bign_params в структуры ASN1
*******************************************************************************
*/

static int evpBign_asn1_params2fieldid(BIGN_FIELDID* field, 
	const bign_params* params)
{
	int ok = 0;
	BIGNUM* p = NULL;
	octet rev[64];
	// минимальный входной контроль
	if (!params || !field)
		return 0;
	// установить fieldType
	if (field->fieldType)
		ASN1_OBJECT_free(field->fieldType);
	if (!(field->fieldType = OBJ_txt2obj(SN_bign_primefield, 0)))
		goto err;
	// установить prime
	memCopy(rev, params->p, params->l / 4);
	memRev(rev, params->l / 4);
	if (!(p = BN_new()) || !BN_bin2bn(rev, params->l / 4, p))
		goto err;
	field->prime = BN_to_ASN1_INTEGER(p, field->prime);
	if (!field->prime)
		goto err;
	ok = 1;
	// выход
err:
	p ? BN_free(p) : 0;
	memSetZero(rev, sizeof(rev));
	return ok;
}

static int evpBign_asn1_params2curve(BIGN_CURVE* curve, 
	const bign_params* params)
{
	// входной контроль
	if (!params || !curve || !curve->a || !curve->b)
		return 0;
	// установить a и b
	if (!ASN1_OCTET_STRING_set(curve->a, params->a, params->l / 4) ||
		!ASN1_OCTET_STRING_set(curve->b, params->b, params->l / 4))
		return 0;
	// установить seed (optional)
	if (!curve->seed && !(curve->seed = ASN1_BIT_STRING_new()))
		return 0;
	curve->seed->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 7);
	curve->seed->flags |= ASN1_STRING_FLAG_BITS_LEFT;
	if (!ASN1_BIT_STRING_set(curve->seed, (octet*)params->seed, 8))
		return 0;
	return 1;
}

static BIGN_ECPARAMS* evpBign_asn1_params2ecp(BIGN_ECPARAMS* ecp, 
	const bign_params* params, bool_t cofactor)
{
	int	ok = 0;
	BIGN_ECPARAMS* ret = ecp;
	BIGNUM* order = 0;
	octet rev[64];
	// входной контроль
	if (!params)
		return 0;
	// подготовить возврат
	if (!ret && !(ret = BIGN_ECPARAMS_new()))
		goto err;
	// установить версию (всегда 1)
	ret->version = 1;
	// установить fieldID
	if (!evpBign_asn1_params2fieldid(ret->fieldID, params))
		goto err;
	// установить кривую
	if (!evpBign_asn1_params2curve(ret->curve, params))
		goto err;
	// установить базовую точку
	if (!ASN1_OCTET_STRING_set(ret->base, params->yG, params->l / 4))
		goto err;
	// установить порядок
	memCopy(rev, params->q, params->l / 4);
	memRev(rev, params->l / 4);
	if (!(order = BN_new()) || !BN_bin2bn(rev, params->l / 4, order))
		goto err;
	ret->order = BN_to_ASN1_INTEGER(order, ret->order);
	if (!ret->order)
		goto err;
	// установить кофактор (optional, всегда 1)
	if (cofactor)
	{
		if (!BN_one(order))
			goto err;
		ret->cofactor = BN_to_ASN1_INTEGER(order, ret->cofactor);
		if (!ret->cofactor)
			goto err;
	}
	ok = 1;
err:	
	if (!ok)
	{
		if (ret && !ecp)
			BIGN_ECPARAMS_free(ret);
		ret = 0;
	}
	order ? BN_free(order) : 0;
	memSetZero(rev, sizeof(rev));
	return ret;
}

static BIGN_DOMAINPARAMS* evpBign_asn1_params2dp(BIGN_DOMAINPARAMS* dp, 
	bool_t* specified, const bign_params* params, bool_t cofactor)
{
	BIGN_DOMAINPARAMS* ret = dp;
	int nid;
	// входной контроль
	if (!params || !specified)
		return 0;
	// подготовка возврата
	if (ret)
	{
		if (ret->type == 0 && ret->value.named)
			ASN1_OBJECT_free(ret->value.named);
		else if (ret->type == 1 && ret->value.specified)
			BIGN_ECPARAMS_free(ret->value.specified);
	}
	else
	{
		ret = BIGN_DOMAINPARAMS_new();
		if (!ret)
			return 0;
	}
	// именованные параметры?
	if (!*specified)
	{
		nid = evpBign_params2nid(params);
		if (nid && (ret->value.named = OBJ_nid2obj(nid)))
			ret->type = 0;
		else
			*specified = TRUE;
	}
	// специфицированные параметры?
	if (*specified)
	{	
		ret->value.specified = evpBign_asn1_params2ecp(0, params, cofactor);
		if (ret->value.specified)
			ret->type = 1;
		else
		{
			if (!dp)
				BIGN_DOMAINPARAMS_free(ret);
			ret = dp;
		}
	}
	return ret;
}

/*
*******************************************************************************
Чтение параметров bign_params из структур ASN.1
*******************************************************************************
*/

static int evpBign_asn1_ecp2params(bign_params* params, 
	const BIGN_ECPARAMS* ecp)
{
	int ok = 0;
	BIGNUM* p = 0;
	// входной контроль
	if (!params || !ecp)
		return 0;
	memSetZero(params, sizeof(bign_params));
	// проверить версию
	if (ecp->version != 1)
		goto err;
	// разобрать описание поля GF(p)
	if (!ecp->fieldID || 
		!ecp->fieldID->fieldType || 
		OBJ_obj2nid(ecp->fieldID->fieldType) != NID_bign_primefield || 
		!ecp->fieldID->prime)
		goto err;
	p = ASN1_INTEGER_to_BN(ecp->fieldID->prime, NULL);
	if (!p)
		goto err;
	if (BN_is_negative(p) || BN_is_zero(p) ||
		(params->l = (size_t)BN_num_bits(p)) != 256 && 
			params->l != 384 && params->l != 512)
		goto err;
	params->l /= 2;
	// загрузить p
	if (!BN_bn2bin(p, params->p))
		goto err;
	memRev(params->p, params->l / 4);
	// загрузить a и b
	if (!ecp->curve || 
		!ecp->curve->a || !ecp->curve->a->data || 
		!ecp->curve->b || !ecp->curve->b->data ||
		ecp->curve->a->length != (int)params->l / 4 ||
		ecp->curve->b->length != (int)params->l / 4)
		goto err;
	memCopy(params->a, ecp->curve->a->data, params->l / 4);
	memCopy(params->b, ecp->curve->b->data, params->l / 4);
	// загрузить seed (optional)
	if (ecp->curve->seed)
	{
		if (ecp->curve->seed->length != 8)
			goto err;
		memCopy(params->seed, ecp->curve->seed->data, 8);
	}
	// загрузить base
	if (!ecp->base || !ecp->base->data || 
		ecp->base->length != (int)params->l / 4)
		goto err;
	memCopy(params->yG, ecp->base->data, params->l / 4);
	// загрузить order
	if ((p = ASN1_INTEGER_to_BN(ecp->order, p)) == NULL)
		goto err;
	if (BN_is_negative(p) || BN_is_zero(p) || 
		BN_num_bits(p) != (int)params->l * 2)
		goto err;
	if (!BN_bn2bin(p, params->q))
		goto err;
	memRev(params->q, params->l / 4);
	// загрузить cofactor (optional)
	if (ecp->cofactor)
	{
		if (!(p = ASN1_INTEGER_to_BN(ecp->cofactor, p)) ||
			!BN_is_one(p))
			goto err;
	}
	ok = 1;
err:
	p ? BN_free(p) : 0;
	return ok;
}

static int evpBign_asn1_dp2params(bign_params* params, bool_t* specified,
	const BIGN_DOMAINPARAMS* dp)
{
	// входной контроль
	if (!params || !specified || !dp)
		return 0;
	// именованные параметры?
	if (dp->type == 0)
	{ 
		if (!evpBign_nid2params(params, OBJ_obj2nid(dp->value.named)))
			return 0;
		*specified = FALSE;
	}
	// специфицированные параметры?
	else if (dp->type == 1)
	{ 
		if (!evpBign_asn1_ecp2params(params, dp->value.specified))
			return 0;
		*specified = TRUE;
	}
	// наследованные параметры?
	else if (dp->type == 2)
	{ 
		*specified = FALSE;
		return 0;
	}
	// неверные параметры?
	else
		return 0;
	return 1;
}

/*
*******************************************************************************
Кодирование и декодирование параметров, вложенных в bign_key

\remark Параметры задаются типом DomainParameters [BIGN_DOMAINPARAMS]
*******************************************************************************
*/

int evpBign_asn1_d2i_params(bign_key* key, bool_t* specified, 
	const octet** in, long len)
{
	BIGN_DOMAINPARAMS* dp;
	int ret;
	// входной контроль
	if (!key || !specified)
		return 0;
	// декодировать в dp
	dp = d2i_BIGN_DOMAINPARAMS(0, in, len);
	if (!dp)
		return 0;
	// разобрать dp
	ret = evpBign_asn1_dp2params(key->params, specified, dp);
	BIGN_DOMAINPARAMS_free(dp);
	return ret;
}

int evpBign_asn1_i2d_params(octet** out, bool_t* specified, 
	const bign_key* key)
{
	bool_t cofactor;
	BIGN_DOMAINPARAMS* dp;
	int ret = 0;
	// входной контроль
	if (!key || !specified)
		return 0;
	// преобразовать в стандартную структуру
	*specified = key->flags & EVP_BIGN_PKEY_ENC_PARAMS_SPECIFIED;
	cofactor = key->flags & EVP_BIGN_PKEY_ENC_PARAMS_COFACTOR;
	dp = evpBign_asn1_params2dp(0, specified, key->params, cofactor);
	if (!dp)
		return 0;
	// кодировать
	ret = i2d_BIGN_DOMAINPARAMS(dp, out);
	BIGN_DOMAINPARAMS_free(dp);
	return ret;
}

/*
*******************************************************************************
Кодирование и декодирование открытого ключа, вложенного в bign_key

\remark Открытый ключ задается типом PublicKey ::= BIT STRING
*******************************************************************************
*/

int evpBign_asn1_o2i_pubkey(bign_key* key, const octet** in, long len)
{
	// входной контроль
	if (!key || !in || len != key->params->l / 2)
		return 0;
	// сохранить ключ
	memCopy(key->pubkey, *in, len);
	memSetZero(key->pubkey + len, sizeof(key->pubkey) - len);
	return 1;
}

int evpBign_asn1_i2o_pubkey(octet** out, const bign_key* key)
{
	int ret;
	// входной контроль
	if (!key)
		return 0;
	// длина ключа в октетах
	ret = key->params->l / 2;
	if (!out)
		return ret;
	// подготовить буфер
	if (!*out && !(*out = (octet*)OPENSSL_malloc(ret)))
		return 0;
	// возвратить ключ
	memCopy(*out, key->pubkey, ret);
	return ret;
}
