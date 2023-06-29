/*
*******************************************************************************
\file belt_md.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief The Belt hashing algorithm (belt-hash)
\created 2013.08.14
\version 2021.03.02
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <bee2/core/blob.h>
#include <bee2/core/mem.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include "bee2evp/bee2evp.h"
#include "bee2evp_lcl.h"

/*
*******************************************************************************
Алгоритм belt_hash
*******************************************************************************
*/

const char OID_belt_hash[] = "1.2.112.0.2.0.34.101.31.81";
const char SN_belt_hash[] = "belt-hash";
const char LN_belt_hash[] = "belt-hash";

EVP_MD* EVP_belt_hash;
const EVP_MD* evpBeltHash()
{
	return EVP_belt_hash;
}

static int evpBeltHash_init(EVP_MD_CTX* ctx) 
{
	void* state = EVP_MD_CTX_md_data(ctx);
	ASSERT(state);
	beltHashStart(state);
	return 1;
}

static int evpBeltHash_update(EVP_MD_CTX* ctx, const void* data, size_t count)
{
	blob_t state = EVP_MD_CTX_md_data(ctx);
	ASSERT(state);
	beltHashStepH(data, count, state);
	return 1;
}

static int evpBeltHash_final(EVP_MD_CTX* ctx, octet* md)
{
	blob_t state = EVP_MD_CTX_md_data(ctx);
	ASSERT(state);
	beltHashStepG(md, state);
	return 1;
}

/*
*******************************************************************************
Регистрация алгоритмов
*******************************************************************************
*/

static int belt_md_nids[128];
static int belt_md_count;

#define BELT_MD_REG(name, tmp)\
	(((tmp = NID_##name) != NID_undef) ?\
		belt_md_nids[belt_md_count++] = tmp :\
		(((tmp = OBJ_create(OID_##name, SN_##name, LN_##name)) > 0) ?\
			belt_md_nids[belt_md_count++] = tmp : NID_undef))

/*
*******************************************************************************
Перечисление алгоритмов
*******************************************************************************
*/

static ENGINE_DIGESTS_PTR prev_enum;

static int evpBeltMD_enum(ENGINE* e, const EVP_MD** md, const int** nids, 
	int nid)
{
	// возвратить таблицу идентификаторов?
	if (!md)
	{
		// объединить таблицы?
		if (prev_enum && prev_enum != evpBeltMD_enum)
		{
			nid = prev_enum(e, md, nids, nid);
			if (nid <= 0)
				return 0;
			if (belt_md_count + nid >= (int)COUNT_OF(belt_md_nids))
				return 0;
			memCopy(belt_md_nids + belt_md_count, *nids, 
				nid * sizeof(int));
			*nids = belt_md_nids;
			return belt_md_count + nid;
		}
		// нет, просто отчитаться за себя
		*nids = belt_md_nids;
		return belt_md_count;
	}
	// обработать запрос
	if (nid == NID_belt_hash)
		*md = EVP_belt_hash;
	else if (prev_enum && prev_enum != evpBeltMD_enum)
		return prev_enum(e, md, nids, nid);
	else
		return 0;
	// ответ найден
	return 1;
}

/*
*******************************************************************************
Подключение / закрытие

\remark EVP_MD::block_size используется при построении HMAC.
\todo Разобраться с ctrl-функцией (EVP_MD_meth_set_ctrl).
\todo Разобраться с EVP_MD::pkey_type (второй параметр EVP_MD_meth_new).
*******************************************************************************
*/

int evpBeltMD_bind(ENGINE* e)
{
	int tmp;
	// зарегистрировать алгоритмы и получить nid'ы
	if (BELT_MD_REG(belt_hash, tmp) == NID_undef)
		return 0;
	// создать и настроить описатель belt_hash
	EVP_belt_hash = EVP_MD_meth_new(NID_belt_hash, 0);
	if (EVP_belt_hash == 0 ||
		!EVP_MD_meth_set_result_size(EVP_belt_hash, 32) ||
		!EVP_MD_meth_set_input_blocksize(EVP_belt_hash, 32) ||
		!EVP_MD_meth_set_app_datasize(EVP_belt_hash, (int)beltHash_keep()) ||
		!EVP_MD_meth_set_init(EVP_belt_hash, evpBeltHash_init) ||
		!EVP_MD_meth_set_update(EVP_belt_hash, evpBeltHash_update) ||
		!EVP_MD_meth_set_final(EVP_belt_hash, evpBeltHash_final))
		return 0;
	// задать перечислитель
	prev_enum = ENGINE_get_digests(e);
	if (!ENGINE_set_digests(e, evpBeltMD_enum)) 
		return 0;
	// зарегистрировать алгоритмы
	return ENGINE_register_digests(e) &&
		EVP_add_digest(EVP_belt_hash);
}

void evpBeltMD_finish()
{
	EVP_MD_meth_free(EVP_belt_hash);
    EVP_belt_hash = 0;
}
