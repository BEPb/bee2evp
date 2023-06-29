/*
*******************************************************************************
\file belt_ameth.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Data formats for belt-macXXX and belt-hmac (hmac-hbelt)
\created 2013.07.01
\version 2021.02.18
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <bee2/core/blob.h>
#include <bee2/core/mem.h>
#include <bee2/core/util.h>
#include "bee2evp/bee2evp.h"

/*
*******************************************************************************
Форматы данных для алгоритмов belt-macXXX

Форматы задаются как ASN.1-методы, через структуру EVP_PKEY_ASN1_METHOD.

\remark ASN.1-методы связываются с алгоритмами ключа имитозащиты.

\remark По мотивам схемы подключения CMAC (openssl/crypto/cmac/cm_ameth.c).

\warning В OpenSSL 1.1.0 в структуре EVP_PKEY_ASN1_METHOD появляется 
дополнительное поле pkey_security_bits. Это поле настраивается с помощью 
функции EVP_PKEY_asn1_set_security_bits.
*******************************************************************************
*/

static int evpBeltMAC_size(const EVP_PKEY* pkey)
{
	return 8;
}

static void evpBeltMAC_key_free(EVP_PKEY* pkey)
{
	blobClose(EVP_PKEY_get0(pkey));
}

static EVP_PKEY_ASN1_METHOD* EVP_belt_mac128_ameth;
static EVP_PKEY_ASN1_METHOD* EVP_belt_mac192_ameth;
static EVP_PKEY_ASN1_METHOD* EVP_belt_mac256_ameth;

const EVP_PKEY_ASN1_METHOD* evpBeltMAC128_ameth()
{
	return EVP_belt_mac128_ameth;
}

const EVP_PKEY_ASN1_METHOD* evpBeltMAC192_ameth()
{
	return EVP_belt_mac192_ameth;
}

const EVP_PKEY_ASN1_METHOD* evpBeltMAC256_ameth()
{
	return EVP_belt_mac256_ameth;
}

/*
*******************************************************************************
Форматы данных для алгоритмов belt-hmac

Форматы задаются как ASN.1-методы, через структуру EVP_PKEY_ASN1_METHOD.

\remark ASN.1-методы связываются с алгоритмами ключа имитозащиты.

\remark По мотивам схемы подключения HMAC (openssl/crypto/hmac/hm_ameth.c).

\warning В OpenSSL 1.1.0 в структуре EVP_PKEY_ASN1_METHOD появляется 
дополнительное поле pkey_security_bits. 
*******************************************************************************
*/

static int evpBeltHMAC_size(const EVP_PKEY* pkey)
{
	return 32;
}

static void evpBeltHMAC_key_free(EVP_PKEY* pkey)
{
	blobClose(EVP_PKEY_get0(pkey));
}

static int evpBeltHMAC_key_ctrl(EVP_PKEY* pkey, int op, long arg1, void* arg2)
{
	switch (op)
	{
	case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
		*(int*)arg2 = NID_belt_hash;
		return 1;
	default:
		return -2;
	}
}

static EVP_PKEY_ASN1_METHOD* EVP_belt_hmac_ameth;

const EVP_PKEY_ASN1_METHOD* evpBeltHMAC_ameth()
{
	return EVP_belt_hmac_ameth;
}

/*
*******************************************************************************
Регистрация методов
*******************************************************************************
*/

static int belt_ameth_nids[128];
static int belt_ameth_count;

#define BELT_AMETH_REG(name, tmp)\
	(((tmp = NID_##name) != NID_undef) ?\
		belt_ameth_nids[belt_ameth_count++] = tmp :\
		(((tmp = OBJ_create(OID_##name, SN_##name, LN_##name)) > 0) ?\
			belt_ameth_nids[belt_ameth_count++] = tmp :	NID_undef))

/*
*******************************************************************************
Перечисление методов

\remark В prev_enum может задаваться указатель на перечислитель, объявленный 
в другом модуле. Тогда таблицы идентификаторов перечислителей объединяются.
*******************************************************************************
*/

static ENGINE_PKEY_ASN1_METHS_PTR prev_enum;

static int evpBelt_ameth_enum(ENGINE* e, EVP_PKEY_ASN1_METHOD** ameth, 
	const int** nids, int nid)
{
	// возвратить таблицу идентификаторов?
	if (!ameth)
	{
		// объединить таблицы?
		if (prev_enum && prev_enum != evpBelt_ameth_enum)
		{
			nid = prev_enum(e, ameth, nids, nid);
			if (nid <= 0)
				return 0;
			if (belt_ameth_count + nid >= (int)COUNT_OF(belt_ameth_nids))
				return 0;
			memCopy(belt_ameth_nids + belt_ameth_count, *nids, 
				nid * sizeof(int));
			*nids = belt_ameth_nids;
			return belt_ameth_count + nid;
		}
		// нет, просто отчитаться за себя
		*nids = belt_ameth_nids;
		return belt_ameth_count;
	}
	// обработать запрос
	if (nid == NID_belt_mac128)
		*ameth = EVP_belt_mac128_ameth;
	else if (nid == NID_belt_mac192)
		*ameth = EVP_belt_mac192_ameth;
	else if (nid == NID_belt_mac256)
		*ameth = EVP_belt_mac256_ameth;
	else if (nid == NID_belt_hmac)
		*ameth = EVP_belt_hmac_ameth;
	else if (prev_enum && prev_enum != evpBelt_ameth_enum)
		return prev_enum(e, ameth, nids, nid);
	else
		return 0;
	// ответ найден
	return 1;
}

/*
*******************************************************************************
Подключение / закрытие

\remark При добавлении в evpBelt_ameth_destroy() вызовов 
EVP_PKEY_asn1_free(EVP_belt_XXX_ameth) будет ошибка: к моменту вызова 
описатели уже освобождены в ядре OpenSSL.
*******************************************************************************
*/

int evpBelt_ameth_bind(ENGINE* e)
{
	int tmp;
	// зарегистрировать методы и получить nid'ы
	if (BELT_AMETH_REG(belt_mac128, tmp) == NID_undef ||
		BELT_AMETH_REG(belt_mac192, tmp) == NID_undef ||
		BELT_AMETH_REG(belt_mac256, tmp) == NID_undef ||
		BELT_AMETH_REG(belt_hmac, tmp) == NID_undef)
		return 0;
	// создать и настроить описатель belt_mac128
	EVP_belt_mac128_ameth = EVP_PKEY_asn1_new(NID_belt_mac128, 0, "belt-mac128", 
		"OpenSSL belt-mac128 method");
	if (EVP_belt_mac128_ameth == 0)
		return 0;
	EVP_PKEY_asn1_set_public(EVP_belt_mac128_ameth, 0, 0, 0, 0, 
		evpBeltMAC_size, 0);
	EVP_PKEY_asn1_set_free(EVP_belt_mac128_ameth, evpBeltMAC_key_free);
	// создать и настроить описатель belt_mac192
	EVP_belt_mac192_ameth = EVP_PKEY_asn1_new(NID_belt_mac192, 0, "belt-mac192", 
		"OpenSSL belt-mac192 method");
	if (EVP_belt_mac192_ameth == 0)
		return 0;
	EVP_PKEY_asn1_set_public(EVP_belt_mac192_ameth, 0, 0, 0, 0, 
		evpBeltMAC_size, 0);
	EVP_PKEY_asn1_set_free(EVP_belt_mac192_ameth, evpBeltMAC_key_free);
	// создать и настроить описатель belt_mac256
	EVP_belt_mac256_ameth = EVP_PKEY_asn1_new(NID_belt_mac256, 0, "belt-mac256", 
		"OpenSSL belt-mac256 method");
	if (EVP_belt_mac256_ameth == 0)
		return 0;
	EVP_PKEY_asn1_set_public(EVP_belt_mac256_ameth, 0, 0, 0, 0, 
		evpBeltMAC_size, 0);
	EVP_PKEY_asn1_set_free(EVP_belt_mac256_ameth, evpBeltMAC_key_free);
	// создать и настроить описатель belt_hmac
	EVP_belt_hmac_ameth = EVP_PKEY_asn1_new(NID_belt_hmac, 0, "belt-hmac", 
		"OpenSSL belt-hmac method");
	if (EVP_belt_hmac_ameth == 0)
		return 0;
	EVP_PKEY_asn1_set_public(EVP_belt_hmac_ameth, 
		0, 0, 0, 0, evpBeltHMAC_size, 0);
	EVP_PKEY_asn1_set_free(EVP_belt_hmac_ameth, evpBeltHMAC_key_free);
	EVP_PKEY_asn1_set_ctrl(EVP_belt_hmac_ameth, evpBeltHMAC_key_ctrl);
	// задать перечислитель
	prev_enum = ENGINE_get_pkey_asn1_meths(e);
	return ENGINE_set_pkey_asn1_meths(e, evpBelt_ameth_enum);
}

void evpBelt_ameth_finish()
{
}
