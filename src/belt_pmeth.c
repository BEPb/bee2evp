/*
*******************************************************************************
\file belt_pmeth.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Methods for belt-macXXX and belt-hmac (hmac-hbelt) keys
\created 2014.09.16
\version 2021.02.18
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <bee2/core/blob.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include "bee2evp/bee2evp.h"

/*
*******************************************************************************
Методы ключей belt_macXXX и belt-hmac (hmac-hbelt)

Алгоритмы имитозащиты belt_macXXX и belt-hmac подключаются как методы 
соответствующих ключей, через структуру EVP_PKEY_METHOD. 

\remark По мотивам схем подключения CMAC (openssl/crypto/cmac/cm_pmeth.c) и 
HMAC (openssl/crypto/hmac/hm_pmeth.c).

\remark Флаг EVP_PKEY_FLAG_SIGCTX_CUSTOM говорит о том, что связанная с ключом 
структура EVP_MD имеет номинальное значение.

\remark В OpenSSL установка ключей выполняется в функции EVP_PKEY_new_mac_key.
Сначала вызывается ctrl-функция с кодом EVP_PKEY_CTRL_SET_MAC_KEY и ключ 
попадает в контекст типа EVP_PKEY_CTX. Затем вызывается функция 
EVP_PKEY_METHOD::keygen(), которая должна переписать ключ из контекста в
структуру типа EVP_PKEY. Естественная генерация ключа напрямую в EVP_PKEY
(без обращения к контексту) не предполагается. Видимо в этой функции 
нет необходимости, поскольку экспорт ключа не предусмотрен и поэтому 
единственно работоспособный подход -- это импорт ключа.

\remark Ключ в EVP_PKEY очищается в функции EVP_PKEY_free через 
вызов EVP_PKEY::ameth->pkey_free.

\remark Ctrl-код EVP_PKEY_CTRL_MD обрабатывается так: если ключ в EVP_PKEY
был задан, то он переписывается в контекст. Если он не был задан, то контекст
очищается. Нужно ли обрабатывать код, как его обрабатывать до конца не понятно.

\remark В реализациях CMAC и HMAC строковая команда "key" означает передачу ключа 
как параметра. Ключ передается как буфер двоичных данных, хотя описывается 
как строка символов. Логика выглядит очень странной и поэтому не поддержана. 
Реализуется логика следующим образом:
\code
static int evpBeltMAC256_pkey_ctrl_str(EVP_PKEY_CTX* ctx, const char* type, 
	const char* value)
{
	...
	// установить ключ, заданный двоичным словом
	if (strEq(type, "key"))
		return memIsValid(value, 32) && evpBeltMAC256_pkey_ctrl(ctx, 
			EVP_PKEY_CTRL_SET_MAC_KEY, 32, (void*)value);
	...
}
\endcode

\todo Предусмотреть строковую команду для загрузки ключа из файла.
\todo Разобраться с EVP_PKEY_CTRL_MD, EVP_PKEY_GET_MD.
\todo Разобраться с EVP_PKEY_CTX::keygen_info_count: в ядре OpenSSL
методы типа _pkey_init заканчиваются строчкой
	ctx->keygen_info_count = 0;
*******************************************************************************
*/

/*
*******************************************************************************
Методы belt_macXXX
*******************************************************************************
*/

static int evpBeltMAC_pkey_init(EVP_PKEY_CTX* ctx)
{
	EVP_PKEY_CTX_set_data(ctx, blobCreate(beltMAC_keep()));
	if (!EVP_PKEY_CTX_get_data(ctx))
		return 0;
	return 1;
}

static int evpBeltMAC_pkey_copy(EVP_PKEY_CTX* dest, EVP_PKEY_CTX* src)
{
	if (!evpBeltMAC_pkey_init(dest))
		return 0;
	memCopy(EVP_PKEY_CTX_get_data(dest), EVP_PKEY_CTX_get_data(src), 
		beltMAC_keep());
	return 1;
}

static void evpBeltMAC_pkey_cleanup(EVP_PKEY_CTX* ctx)
{
	blobClose(EVP_PKEY_CTX_get_data(ctx));
}

static int evpBeltMAC128_pkey_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY* pkey)
{
	void* state = blobCreate(beltMAC_keep());
	if (!state)
		return 0;
	memCopy(state, EVP_PKEY_CTX_get_data(ctx), beltMAC_keep());
	return EVP_PKEY_assign(pkey, NID_belt_mac128, state);
}

static int evpBeltMAC192_pkey_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY* pkey)
{
	void* state = blobCreate(beltMAC_keep());
	if (!state)
		return 0;
	memCopy(state, EVP_PKEY_CTX_get_data(ctx), beltMAC_keep());
	return EVP_PKEY_assign(pkey, NID_belt_mac192, state);
}

static int evpBeltMAC256_pkey_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY* pkey)
{
	void* state = blobCreate(beltMAC_keep());
	if (!state)
		return 0;
	memCopy(state, EVP_PKEY_CTX_get_data(ctx), beltMAC_keep());
	return EVP_PKEY_assign(pkey, NID_belt_mac256, state);
}

static int evpBeltMAC_pkey_int_update(EVP_MD_CTX* ctx, const void* data, 
	size_t count)
{
	beltMACStepA(data, count, EVP_PKEY_CTX_get_data(EVP_MD_CTX_pkey_ctx(ctx)));
	return 1;
}

static int evpBeltMAC_signctx_init(EVP_PKEY_CTX* ctx, EVP_MD_CTX* mctx)
{
	EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
	EVP_MD_CTX_set_update_fn(mctx, evpBeltMAC_pkey_int_update);
	return 1;
}

static int evpBeltMAC_signctx(EVP_PKEY_CTX* ctx, octet* sig, size_t* siglen,
	EVP_MD_CTX* mctx)
{
	beltMACStepG(sig, EVP_PKEY_CTX_get_data(ctx));
	*siglen = 8;
	return 1;
}

static int evpBeltMAC128_pkey_ctrl(EVP_PKEY_CTX* ctx, int type, int p1, void* p2)
{
	EVP_PKEY* pkey;
	switch (type)
	{
	case EVP_PKEY_CTRL_SET_MAC_KEY:
		if (p1 != 16 || !p2 || !EVP_PKEY_CTX_get_data(ctx))
			return 0;
		beltMACStart(EVP_PKEY_CTX_get_data(ctx), (const octet*)p2, p1);
		break;
	case EVP_PKEY_CTRL_MD:
		if (pkey = EVP_PKEY_CTX_get0_pkey(ctx))
			memCopy(EVP_PKEY_CTX_get_data(ctx), EVP_PKEY_get0(pkey), 
				beltMAC_keep());
		else
			memWipe(EVP_PKEY_CTX_get_data(ctx), beltMAC_keep());
		break;
	default:
		return -2;
	}
	return 1;
}

static int evpBeltMAC192_pkey_ctrl(EVP_PKEY_CTX* ctx, int type, int p1, void* p2)
{
	EVP_PKEY* pkey;
	switch (type)
	{
	case EVP_PKEY_CTRL_SET_MAC_KEY:
		if (p1 != 24 || !p2 || !EVP_PKEY_CTX_get_data(ctx))
			return 0;
		beltMACStart(EVP_PKEY_CTX_get_data(ctx), (const octet*)p2, p1);
		break;
	case EVP_PKEY_CTRL_MD:
		if (pkey = EVP_PKEY_CTX_get0_pkey(ctx))
			memCopy(EVP_PKEY_CTX_get_data(ctx), EVP_PKEY_get0(pkey), 
				beltMAC_keep());
		else
			memWipe(EVP_PKEY_CTX_get_data(ctx), beltMAC_keep());
		break;
	default:
		return -2;
	}
	return 1;
}

static int evpBeltMAC256_pkey_ctrl(EVP_PKEY_CTX* ctx, int type, int p1, void* p2)
{
	EVP_PKEY* pkey;
	switch (type)
	{
	case EVP_PKEY_CTRL_SET_MAC_KEY:
		if (p1 != 32 || !p2 || !EVP_PKEY_CTX_get_data(ctx))
			return 0;
		beltMACStart(EVP_PKEY_CTX_get_data(ctx), (const octet*)p2, p1);
		break;
	case EVP_PKEY_CTRL_MD:
		if (pkey = EVP_PKEY_CTX_get0_pkey(ctx))
			memCopy(EVP_PKEY_CTX_get_data(ctx), EVP_PKEY_get0(pkey), 
				beltMAC_keep());
		else
			memWipe(EVP_PKEY_CTX_get_data(ctx), beltMAC_keep());
		break;
	default:
		return -2;
	}
	return 1;
}

static int evpBeltMAC128_pkey_ctrl_str(EVP_PKEY_CTX* ctx, const char* type, 
	const char* value)
{
	if (!value)
		return 0;
	// установить ключ, заданный шестнадцатеричной строкой
	if (strEq(type, "hexkey"))
	{
		void* key;
		int ret;
		if (strLen(value) != 32 || !hexIsValid(value))
			return 0;
		if (!(key = blobCreate(16)))
			return 0;
		hexTo(key, value);
		ret = evpBeltMAC128_pkey_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, 16, key);
		blobClose(key);
		return ret;
	}
	return -2;
}

static int evpBeltMAC192_pkey_ctrl_str(EVP_PKEY_CTX* ctx, const char* type, 
	const char* value)
{
	if (!value)
		return 0;
	// установить ключ, заданный шестнадцатеричной строкой
	if (strEq(type, "hexkey"))
	{
		void* key;
		int ret;
		if (strLen(value) != 48 || !hexIsValid(value))
			return 0;
		if (!(key = blobCreate(24)))
			return 0;
		hexTo(key, value);
		ret = evpBeltMAC192_pkey_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, 24, key);
		blobClose(key);
		return ret;
	}
	return -2;
}

static int evpBeltMAC256_pkey_ctrl_str(EVP_PKEY_CTX* ctx, const char* type, 
	const char* value)
{
	if (!value)
		return 0;
	// установить ключ, заданный шестнадцатеричной строкой
	if (strEq(type, "hexkey"))
	{
		void* key;
		int ret;
		if (strLen(value) != 64 || !hexIsValid(value))
			return 0;
		if (!(key = blobCreate(32)))
			return 0;
		hexTo(key, value);
		ret = evpBeltMAC256_pkey_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, 32, key);
		blobClose(key);
		return ret;
	}
	return -2;
}

/*
*******************************************************************************
Описания belt_mac
*******************************************************************************
*/

const char OID_belt_mac128[] = "1.2.112.0.2.0.34.101.31.51";
const char SN_belt_mac128[] = "belt-mac128";
const char LN_belt_mac128[] = "belt-mac128";

static EVP_PKEY_METHOD* EVP_belt_mac128_pmeth;

const EVP_PKEY_METHOD* evpBeltMAC128_pmeth()
{
	return EVP_belt_mac128_pmeth;
}

const char OID_belt_mac192[] = "1.2.112.0.2.0.34.101.31.52";
const char SN_belt_mac192[] = "belt-mac192";
const char LN_belt_mac192[] = "belt-mac192";

static EVP_PKEY_METHOD* EVP_belt_mac192_pmeth;

const EVP_PKEY_METHOD* evpBeltMAC192_pmeth()
{
	return EVP_belt_mac192_pmeth;
}

const char OID_belt_mac256[] = "1.2.112.0.2.0.34.101.31.53";
const char SN_belt_mac256[] = "belt-mac256";
const char LN_belt_mac256[] = "belt-mac256";

static EVP_PKEY_METHOD* EVP_belt_mac256_pmeth;

const EVP_PKEY_METHOD* evpBeltMAC256_pmeth()
{
	return EVP_belt_mac256_pmeth;
}

/*
*******************************************************************************
Методы belt_hmac
*******************************************************************************
*/

static int evpBeltHMAC_pkey_init(EVP_PKEY_CTX* ctx)
{
	EVP_PKEY_CTX_set_data(ctx, blobCreate(beltHMAC_keep()));
	if (!EVP_PKEY_CTX_get_data(ctx))
		return 0;
	return 1;
}

static int evpBeltHMAC_pkey_copy(EVP_PKEY_CTX* dest, EVP_PKEY_CTX* src)
{
	if (!evpBeltHMAC_pkey_init(dest))
		return 0;
	memCopy(EVP_PKEY_CTX_get_data(dest), EVP_PKEY_CTX_get_data(src), 
		beltHMAC_keep());
	return 1;
}

static void evpBeltHMAC_pkey_cleanup(EVP_PKEY_CTX* ctx)
{
	blobClose(EVP_PKEY_CTX_get_data(ctx));
}

static int evpBeltHMAC_pkey_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY* pkey)
{
	void* state = blobCreate(beltHMAC_keep());
	if (!state)
		return 0;
	memCopy(state, EVP_PKEY_CTX_get_data(ctx), beltHMAC_keep());
	return EVP_PKEY_assign(pkey, NID_belt_hmac, state);
}

static int evpBeltHMAC_pkey_int_update(EVP_MD_CTX* ctx, const void* data, 
	size_t count)
{
	beltHMACStepA(data, count, 
		EVP_PKEY_CTX_get_data(EVP_MD_CTX_pkey_ctx(ctx)));
	return 1;
}

static int evpBeltHMAC_signctx_init(EVP_PKEY_CTX* ctx, EVP_MD_CTX* mctx)
{
	EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
	EVP_MD_CTX_set_update_fn(mctx, evpBeltHMAC_pkey_int_update);
	return 1;
}

static int evpBeltHMAC_signctx(EVP_PKEY_CTX* ctx, octet* sig, size_t* siglen,
	EVP_MD_CTX* mctx)
{
	beltHMACStepG(sig, EVP_PKEY_CTX_get_data(ctx));
	*siglen = 32;
	return 1;
}

static int evpBeltHMAC_pkey_ctrl(EVP_PKEY_CTX* ctx, int type, int p1, void* p2)
{
	EVP_PKEY* pkey;
	switch (type)
	{
	case EVP_PKEY_CTRL_SET_MAC_KEY:
		if (p1 <= 0)
			return 0;
		beltHMACStart(EVP_PKEY_CTX_get_data(ctx), (const octet*)p2, (size_t)p1);
		break;
	case EVP_PKEY_CTRL_MD:
		if (pkey = EVP_PKEY_CTX_get0_pkey(ctx))
			memCopy(EVP_PKEY_CTX_get_data(ctx), EVP_PKEY_get0(pkey),
				beltHMAC_keep());
		else
			memWipe(EVP_PKEY_CTX_get_data(ctx), beltHMAC_keep());
		break;
	default:
		return -2;
	}
	return 1;
}

static int evpBeltHMAC_pkey_ctrl_str(EVP_PKEY_CTX* ctx, const char* type, 
	const char* value)
{
	if (!value)
		return 0;
	// установить ключ, заданный шестнадцатеричной строкой
	if (strEq(type, "hexkey"))
	{
		void* key;
		size_t len;
		int ret;
		if (!hexIsValid(value) || (len = strLen(value)) % 2 || (len /= 2) == 0)
			return 0;
		if (!(key = blobCreate(len)))
			return 0;
		hexTo(key, value);
		ret = evpBeltHMAC_pkey_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, 
			(int)len, key);
		blobClose(key);
		return ret;
	}
	return -2;
}

/*
*******************************************************************************
Описания belt_hmac
*******************************************************************************
*/

const char OID_belt_hmac[] = "1.2.112.0.2.0.34.101.47.12";
const char SN_belt_hmac[] = "belt-hmac";
const char LN_belt_hmac[] = "belt-hmac";

static EVP_PKEY_METHOD* EVP_belt_hmac_pmeth;

const EVP_PKEY_METHOD* evpBeltHMAC_pmeth()
{
	return EVP_belt_hmac_pmeth;
}

/*
*******************************************************************************
Регистрация методов
*******************************************************************************
*/

static int belt_pmeth_nids[128];
static int belt_pmeth_count;

#define BELT_PMETH_REG(name, tmp)\
	(((tmp = NID_##name) != NID_undef) ?\
		belt_pmeth_nids[belt_pmeth_count++] = tmp :\
		(((tmp = OBJ_create(OID_##name, SN_##name, LN_##name)) > 0) ?\
			belt_pmeth_nids[belt_pmeth_count++] = tmp : NID_undef))

/*
*******************************************************************************
Перечисление методов

\remark В prev_enum может задаваться указатель на перечислитель, объявленный 
в другом модуле. Тогда таблицы идентификаторов перечислителей объединяются.
*******************************************************************************
*/

static ENGINE_PKEY_METHS_PTR prev_enum;

static int evpBelt_pmeth_enum(ENGINE* e, EVP_PKEY_METHOD** pmeth, 
	const int** nids, int nid)
{
	// возвратить таблицу идентификаторов?
	if (!pmeth)
	{
		// объединить таблицы?
		if (prev_enum && prev_enum != evpBelt_pmeth_enum)
		{
			nid = prev_enum(e, pmeth, nids, nid);
			if (nid <= 0)
				return 0;
			if (belt_pmeth_count + nid >= (int)COUNT_OF(belt_pmeth_nids))
				return 0;
			memCopy(belt_pmeth_nids + belt_pmeth_count, *nids, 
				nid * sizeof(int));
			*nids = belt_pmeth_nids;
			return nid + belt_pmeth_count;
		}
		// нет, просто отчитаться за себя
		*nids = belt_pmeth_nids;
		return belt_pmeth_count;
	}
	// обработать запрос
	if (nid == NID_belt_mac128)
		*pmeth = EVP_belt_mac128_pmeth;
	else if (nid == NID_belt_mac192)
		*pmeth = EVP_belt_mac192_pmeth;
	else if (nid == NID_belt_mac256)
		*pmeth = EVP_belt_mac256_pmeth;
	else if (nid == NID_belt_hmac)
		*pmeth = EVP_belt_hmac_pmeth;
	else if (prev_enum && prev_enum != evpBelt_pmeth_enum)
		return prev_enum(e, pmeth, nids, nid);
	else
		return 0;
	// ответ найден
	return 1;
}

/*
*******************************************************************************
Подключение / закрытие

\remark При добавлении в evpBelt_pmeth_destroy() вызовов 
EVP_PKEY_meth_free(EVP_belt_XXX_pmeth) будет ошибка: к моменту вызова 
описатели уже освобождены в ядре OpenSSL.
*******************************************************************************
*/

int evpBelt_pmeth_bind(ENGINE* e)
{
	int tmp;
	// зарегистрировать методы и получить nid'ы
	if (BELT_PMETH_REG(belt_mac128, tmp) == NID_undef ||
		BELT_PMETH_REG(belt_mac192, tmp) == NID_undef ||
		BELT_PMETH_REG(belt_mac256, tmp) == NID_undef ||
		BELT_PMETH_REG(belt_hmac, tmp) == NID_undef)
		return 0;
	// создать и настроить описатель belt_mac128
	EVP_belt_mac128_pmeth = EVP_PKEY_meth_new(NID_belt_mac128, 
		EVP_PKEY_FLAG_SIGCTX_CUSTOM);
	if (EVP_belt_mac128_pmeth == 0)
		return 0;
	EVP_PKEY_meth_set_init(EVP_belt_mac128_pmeth, evpBeltMAC_pkey_init);
	EVP_PKEY_meth_set_copy(EVP_belt_mac128_pmeth, evpBeltMAC_pkey_copy);
	EVP_PKEY_meth_set_cleanup(EVP_belt_mac128_pmeth, evpBeltMAC_pkey_cleanup);
	EVP_PKEY_meth_set_keygen(EVP_belt_mac128_pmeth, 0, evpBeltMAC128_pkey_keygen);
	EVP_PKEY_meth_set_signctx(EVP_belt_mac128_pmeth, evpBeltMAC_signctx_init, 
		evpBeltMAC_signctx);
	EVP_PKEY_meth_set_ctrl(EVP_belt_mac128_pmeth, evpBeltMAC128_pkey_ctrl, 
		evpBeltMAC128_pkey_ctrl_str);
	// создать и настроить описатель belt_mac192
	EVP_belt_mac192_pmeth = EVP_PKEY_meth_new(NID_belt_mac192, 
		EVP_PKEY_FLAG_SIGCTX_CUSTOM);
	if (EVP_belt_mac192_pmeth == 0)
		return 0;
	EVP_PKEY_meth_set_init(EVP_belt_mac192_pmeth, evpBeltMAC_pkey_init);
	EVP_PKEY_meth_set_copy(EVP_belt_mac192_pmeth, evpBeltMAC_pkey_copy);
	EVP_PKEY_meth_set_cleanup(EVP_belt_mac192_pmeth, evpBeltMAC_pkey_cleanup);
	EVP_PKEY_meth_set_keygen(EVP_belt_mac192_pmeth, 0, evpBeltMAC192_pkey_keygen);
	EVP_PKEY_meth_set_signctx(EVP_belt_mac192_pmeth, evpBeltMAC_signctx_init, 
		evpBeltMAC_signctx);
	EVP_PKEY_meth_set_ctrl(EVP_belt_mac192_pmeth, evpBeltMAC192_pkey_ctrl, 
		evpBeltMAC192_pkey_ctrl_str);
	// создать и настроить описатель belt_mac256
	EVP_belt_mac256_pmeth = EVP_PKEY_meth_new(NID_belt_mac256, 
		EVP_PKEY_FLAG_SIGCTX_CUSTOM);
	if (EVP_belt_mac256_pmeth == 0)
		return 0;
	EVP_PKEY_meth_set_init(EVP_belt_mac256_pmeth, evpBeltMAC_pkey_init);
	EVP_PKEY_meth_set_copy(EVP_belt_mac256_pmeth, evpBeltMAC_pkey_copy);
	EVP_PKEY_meth_set_cleanup(EVP_belt_mac256_pmeth, evpBeltMAC_pkey_cleanup);
	EVP_PKEY_meth_set_keygen(EVP_belt_mac256_pmeth, 0, evpBeltMAC256_pkey_keygen);
	EVP_PKEY_meth_set_signctx(EVP_belt_mac256_pmeth, evpBeltMAC_signctx_init, 
		evpBeltMAC_signctx);
	EVP_PKEY_meth_set_ctrl(EVP_belt_mac256_pmeth, evpBeltMAC256_pkey_ctrl, 
		evpBeltMAC256_pkey_ctrl_str);
	// ...belt_hmac
	EVP_belt_hmac_pmeth = EVP_PKEY_meth_new(NID_belt_hmac, 
		EVP_PKEY_FLAG_SIGCTX_CUSTOM);
	if (EVP_belt_hmac_pmeth == 0)
		return 0;
	EVP_PKEY_meth_set_init(EVP_belt_hmac_pmeth, evpBeltHMAC_pkey_init);
	EVP_PKEY_meth_set_copy(EVP_belt_hmac_pmeth, evpBeltHMAC_pkey_copy);
	EVP_PKEY_meth_set_cleanup(EVP_belt_hmac_pmeth, evpBeltHMAC_pkey_cleanup);
	EVP_PKEY_meth_set_keygen(EVP_belt_hmac_pmeth, 0, evpBeltHMAC_pkey_keygen);
	EVP_PKEY_meth_set_signctx(EVP_belt_hmac_pmeth, evpBeltHMAC_signctx_init, 
		evpBeltHMAC_signctx);
	EVP_PKEY_meth_set_ctrl(EVP_belt_hmac_pmeth, evpBeltHMAC_pkey_ctrl, 
		evpBeltHMAC_pkey_ctrl_str);
	// задать перечислитель и зарегистрировать алгоритмы
	prev_enum = ENGINE_get_pkey_meths(e);
	return ENGINE_set_pkey_meths(e, evpBelt_pmeth_enum); 
}

void evpBelt_pmeth_finish()
{
}
