/*
*******************************************************************************
\file bee2evp.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Registration of bee2evp in OpenSSL
\created 2014.11.06
\version 2021.06.24
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <bee2/core/mem.h>
#include <bee2/core/mt.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include "bee2evp/bee2evp.h"
#include "bee2evp_lcl.h"

/*
*******************************************************************************
Реквизиты библиотеки bee2evp
*******************************************************************************
*/

const char SN_bee2evp[] = "bee2evp";
const char LN_bee2evp[] = "Bee2evp Engine [belt + bign + bash]";

/*
*******************************************************************************
Интерфейс плагина

\remark Выдержка из https://eprint.iacr.org/2018/354:
- the bind() method is called by the OpenSSL built-in dynamic ENGINE upon
  load and is used to set the internal state of the ENGINE object and allocate
  needed resources, to set its id and name, and the pointers to the init(),
  finish(), and destroy() functions;
- the init() function is called to derive a fully initialized functional
  reference to the ENGINE from a structural reference;
- the finish() function is called when releasing an ENGINE functional
  reference, to free up any resource allocated to it;
- the destroy() function is called upon unloading the ENGINE, when the last
  structural reference to it is released, to cleanly free any resource
  allocated upon loading it into memory.

\todo С помощью функции 
\code 
static err_t rngReadOpenssl(size_t* read, void* buf, size_t count, void* file)
{
	ASSERT(memIsValid(read, O_PER_S));
	ASSERT(memIsValid(buf, count));
	if ((size_t)(int)count == count && RAND_priv_bytes(buf, (int)count))
		*read = count;
	else
		*read = 0;
	return ERR_OK;
}
\endcode
можно усилить батарею источников энтропии, заменив в функции bee2evp_init() 
строчку 
\code
	if (rngCreate(0, 0) != ERR_OK)
\endcode
на строчку
\code
	if (rngCreate(rngReadOpenssl, 0) != ERR_OK)
\endcode
Однако вызов rngReadOpenssl() в момент инициализации плагина приводит 
к ошибке в дальнейшей работе OpenSSL. Разобраться.
*******************************************************************************
*/

static int bee2evp_init(ENGINE* e)
{
	if (rngCreate(0, 0) != ERR_OK)
		return 0;
	return 1;
}

static int bee2evp_finish(ENGINE* e)
{ 
	evpBeltCipher_finish();
	evpBeltMD_finish();
	evpBelt_pmeth_finish();
	evpBelt_ameth_finish();
	evpBeltPBKDF_finish();
	evpBeltTLS_finish();
	evpBign_pmeth_finish();
	evpBign_ameth_finish();
	evpBash_finish();
	rngClose();
	return 1;
}

static int bee2evp_destroy(ENGINE* e)
{ 
		return 1;
}

static const ENGINE_CMD_DEFN bee2evp_cmd_defns[] = 
{
	{0, 0, 0, 0},
};

static int bee2evp_ctrl(ENGINE* e, int cmd, long i, void* p, void (*f)(void))
{
	return 0;
}

/*
*******************************************************************************
Связывание

\remark Алгоритмы NID_bign_with_hspec, NID_bign_with_hbelt, 
NID_bign_with_bashXXX связываются с неопределенными алгоритмами хэширования. 
При этом навязывается вызов функций интерфейса 
EVP_PKEY_ASN1_METHOD::item_verify() и, как следствие, проверка параметров 
алгоритмов ЭЦП (см. комментарии к функции evpBign_item_verify()).
*******************************************************************************
*/

static int bee2evp_bind(ENGINE* e, const char* id)
{
	// другой идентификатор?
	if (id && strCmp(id, SN_bee2evp) != 0)
		return 0;
	// настроить плагин
	if (!ENGINE_set_id(e, SN_bee2evp) ||
		!ENGINE_set_name(e, LN_bee2evp) ||
		!ENGINE_set_init_function(e, bee2evp_init) ||
		!ENGINE_set_finish_function(e, bee2evp_finish) ||
		!ENGINE_set_destroy_function(e, bee2evp_destroy) ||
		!ENGINE_set_cmd_defns(e, bee2evp_cmd_defns) ||
		!ENGINE_set_ctrl_function(e, bee2evp_ctrl))
		return 0;
	// встроить модули
	if (!evpBeltCipher_bind(e) ||
		!evpBeltMD_bind(e) ||
		!evpBelt_ameth_bind(e) ||
		!evpBelt_pmeth_bind(e) ||
		!evpBeltPBKDF_bind(e) ||
		!evpBeltTLS_bind(e) ||
		!evpBign_ameth_bind(e) ||
		!evpBign_pmeth_bind(e) ||
		!evpBash_bind(e))
		return 0;
	// связать хэш + ЭЦП
	if (!OBJ_add_sigid(NID_bign_with_hbelt, NID_undef, NID_bign_pubkey) ||
		!OBJ_add_sigid(NID_bign_with_bash256, NID_undef, NID_bign_pubkey) ||
		!OBJ_add_sigid(NID_bign_with_bash384, NID_undef, NID_bign_pubkey) ||
		!OBJ_add_sigid(NID_bign_with_bash512, NID_undef, NID_bign_pubkey) ||
		!OBJ_add_sigid(NID_bign_with_hspec, NID_undef, NID_bign_pubkey))
		return 0;
	// связать belt-pbkdf + belt-hmac
	if (!EVP_PBE_alg_add_type(EVP_PBE_TYPE_PRF, NID_belt_hmac, -1, 
		NID_belt_hash, evpBeltPBKDF_keyivgen))
		return 0;
	// все нормально
	return 1;
}

/*
*******************************************************************************
Загрузка в среде OpenSSL
*******************************************************************************
*/

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
	IMPLEMENT_DYNAMIC_CHECK_FN()
	IMPLEMENT_DYNAMIC_BIND_FN(bee2evp_bind)
#endif

static ENGINE* ENGINE_bee2evp()
{
	ENGINE* ret = ENGINE_new();
	if(ret == 0)
		return 0;
	if (!bee2evp_bind(ret, SN_bee2evp))
	{
		ENGINE_free(ret);
		return 0;
	}
	return ret;
}

void ENGINE_load_bee2evp()
{
	ENGINE* e = ENGINE_bee2evp();
	if (e)
	{
		ENGINE_add(e);
		ENGINE_free(e);
		ERR_clear_error();
	}
}
