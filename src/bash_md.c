/*
*******************************************************************************
\file bash_md.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief The Bash hashing algorithm (bash)
\created 2016.09.20
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
#include <bee2/crypto/bash.h>
#include "bee2evp/bee2evp.h"
#include "bee2evp_lcl.h"

/*
*******************************************************************************
Алгоритмы bash
*******************************************************************************
*/

const char OID_bash256[] = "1.2.112.0.2.0.34.101.77.11";
const char SN_bash256[] = "bash256";
const char LN_bash256[] = "bash256";

const char OID_bash384[] = "1.2.112.0.2.0.34.101.77.12";
const char SN_bash384[] = "bash384";
const char LN_bash384[] = "bash384";

const char OID_bash512[] = "1.2.112.0.2.0.34.101.77.13";
const char SN_bash512[] = "bash512";
const char LN_bash512[] = "bash512";

static EVP_MD* EVP_bash256;
const EVP_MD* evpBash256()
{
	return EVP_bash256;
}

static EVP_MD* EVP_bash384;
const EVP_MD* evpBash384()
{
	return EVP_bash384;
}

static EVP_MD* EVP_bash512;
const EVP_MD* evpBash512()
{
	return EVP_bash512;
}

static int evpBash_init(EVP_MD_CTX* ctx) 
{
	void* state = EVP_MD_CTX_md_data(ctx);
	size_t md_len = (size_t)EVP_MD_meth_get_result_size(EVP_MD_CTX_md(ctx));
	ASSERT(state);
	ASSERT(md_len == 32 || md_len == 48 || md_len == 64);
	bashHashStart(state, md_len * 4);
	return 1;
}

static int evpBash_update(EVP_MD_CTX* ctx, const void* data, size_t count)
{
	void* state = EVP_MD_CTX_md_data(ctx);
	ASSERT(state);
	bashHashStepH(data, count, state);
	return 1;
}

static int evpBash_final(EVP_MD_CTX* ctx, octet* md)
{
	void* state = EVP_MD_CTX_md_data(ctx);
	size_t md_len = (size_t)EVP_MD_meth_get_result_size(EVP_MD_CTX_md(ctx));
	ASSERT(state);
	bashHashStepG(md, md_len, state);
	return 1;
}

/*
*******************************************************************************
Регистрация алгоритмов
*******************************************************************************
*/

static int bash_md_nids[128];
static int bash_md_count;

#define BASH_MD_REG(name, tmp)\
	(((tmp = NID_##name) != NID_undef) ?\
		bash_md_nids[bash_md_count++] = tmp :\
		(((tmp = OBJ_create(OID_##name, SN_##name, LN_##name)) > 0) ?\
			bash_md_nids[bash_md_count++] = tmp : NID_undef))

/*
*******************************************************************************
Перечисление алгоритмов
*******************************************************************************
*/

static ENGINE_DIGESTS_PTR prev_enum;

static int evpBash_enum(ENGINE* e, const EVP_MD** md, const int** nids, 
	int nid)
{
	// возвратить таблицу идентификаторов?
	if (!md)
	{
		// объединить таблицы?
		if (prev_enum && prev_enum != evpBash_enum)
		{
			nid = prev_enum(e, md, nids, nid);
			if (nid <= 0)
				return 0;
			if (bash_md_count + nid >= (int)COUNT_OF(bash_md_nids))
				return 0;
			memCopy(bash_md_nids + bash_md_count, *nids, 
				nid * sizeof(int));
			*nids = bash_md_nids;
			return bash_md_count + nid;
		}
		// нет, просто отчитаться за себя
		*nids = bash_md_nids;
		return bash_md_count;
	}
	// обработать запрос
	if (nid == NID_bash256)
		*md = EVP_bash256;
	else if (nid == NID_bash384)
		*md = EVP_bash384;
	else if (nid == NID_bash512)
		*md = EVP_bash512;
	else if (prev_enum && prev_enum != evpBash_enum)
		return prev_enum(e, md, nids, nid);
	else
		return 0;
	// ответ найден
	return 1;
}

/*
*******************************************************************************
Подключение / закрытие

\warning EVP_MD::block_size используется при построении HMAC. Но HMAC 
над sponge-конструкциями, вообще говоря, не определен.
\todo Разобраться с ctrl-функцией (EVP_MD_meth_set_ctrl).
\todo Разобраться с EVP_MD::pkey_type (второй параметр EVP_MD_meth_new).
*******************************************************************************
*/

int evpBash_bind(ENGINE* e)
{
	int tmp;
	// зарегистрировать алгоритмы и получить nid'ы
	if (BASH_MD_REG(bash256, tmp) == NID_undef ||
		BASH_MD_REG(bash384, tmp) == NID_undef ||
		BASH_MD_REG(bash512, tmp) == NID_undef)
		return 0;
	// создать и настроить описатель bash256
	EVP_bash256 = EVP_MD_meth_new(NID_bash256, 0);
	if (EVP_bash256 == 0 ||
		!EVP_MD_meth_set_result_size(EVP_bash256, 32) ||
		!EVP_MD_meth_set_input_blocksize(EVP_bash256, 128) ||
		!EVP_MD_meth_set_app_datasize(EVP_bash256, (int)bashHash_keep()) ||
		!EVP_MD_meth_set_init(EVP_bash256, evpBash_init) ||
		!EVP_MD_meth_set_update(EVP_bash256, evpBash_update) ||
		!EVP_MD_meth_set_final(EVP_bash256, evpBash_final))
		return 0;
	// создать и настроить описатель bash384
	EVP_bash384 = EVP_MD_meth_new(NID_bash384, 0);
	if (EVP_bash384 == 0 ||
		!EVP_MD_meth_set_result_size(EVP_bash384, 48) ||
		!EVP_MD_meth_set_input_blocksize(EVP_bash384, 96) ||
		!EVP_MD_meth_set_app_datasize(EVP_bash384, (int)bashHash_keep()) ||
		!EVP_MD_meth_set_init(EVP_bash384, evpBash_init) ||
		!EVP_MD_meth_set_update(EVP_bash384, evpBash_update) ||
		!EVP_MD_meth_set_final(EVP_bash384, evpBash_final))
		return 0;
	// создать и настроить описатель bash512
	EVP_bash512 = EVP_MD_meth_new(NID_bash512, 0);
	if (EVP_bash512 == 0 ||
		!EVP_MD_meth_set_result_size(EVP_bash512, 64) ||
		!EVP_MD_meth_set_input_blocksize(EVP_bash512, 64) ||
		!EVP_MD_meth_set_app_datasize(EVP_bash512, (int)bashHash_keep()) ||
		!EVP_MD_meth_set_init(EVP_bash512, evpBash_init) ||
		!EVP_MD_meth_set_update(EVP_bash512, evpBash_update) ||
		!EVP_MD_meth_set_final(EVP_bash512, evpBash_final))
		return 0;
	// задать перечислитель
	prev_enum = ENGINE_get_digests(e);
	if (!ENGINE_set_digests(e, evpBash_enum)) 
		return 0;
	// зарегистрировать алгоритмы
	return ENGINE_register_digests(e) &&
		EVP_add_digest(EVP_bash256) &&
		EVP_add_digest(EVP_bash384) &&
		EVP_add_digest(EVP_bash512);
}

void evpBash_finish()
{
	EVP_MD_meth_free(EVP_bash512);
	EVP_bash512 = 0;
	EVP_MD_meth_free(EVP_bash384);
	EVP_bash384 = 0;
	EVP_MD_meth_free(EVP_bash256);
    EVP_bash256 = 0;
}
