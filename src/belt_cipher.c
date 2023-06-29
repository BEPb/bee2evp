/*
*******************************************************************************
\file belt_cipher.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Belt encryption algorithms
\created 2014.10.14
\version 2021.07.14
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <bee2/core/blob.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include "bee2evp/bee2evp.h"
#include "bee2evp_lcl.h"

/*
*******************************************************************************
Общие замечания

\remark Флаг EVP_CIPH_RAND_KEY в описании алгоритма говорит системе, что для 
генерации ключей требуется обратиться к ctrl-функции. Генерация ключей 
выполняется с помощью генератора bee2/rng.

\remark Команда EVP_CTRL_PBE_PRF_NID позволяет объявить 
идентификатор prf-функции, которая будет использоваться для построения ключа 
шифрования по паролю в механизме PBKDF2 (см. openssl\crypto\asn1\p5_pbev2.c).

\remark Если в EVP_CIPHER::flags не установлен флаг EVP_CIPH_CUSTOM_IV,
то функция EVP_CIPHER::init не обязана настраивать синхропосылку 
в режимах CFB, CBC, CTR --- за нее это делает среда OpenSSL 
(см. crypto/evp/evp_enc.c::EVP_CipherInit_ex). 
Настройка в режимах CFB, OFB и CBC (evpBeltXXX_init):
\code
	if (iv)
		memcpy(EVP_CIPHER_CTX_original_iv(ctx), 
			iv, EVP_CIPHER_CTX_iv_length(ctx));
	if (key)
		memcpy(EVP_CIPHER_CTX_iv(ctx), EVP_CIPHER_CTX_original_iv(ctx), 
			EVP_CIPHER_CTX_iv_length(ctx));
\endcode

\remark Если в EVP_CIPHER::flags не установлен флаг EVP_CIPH_ALWAYS_CALL_INIT,
то функция EVP_CIPHER::init не получит управление с нулевым key
(см. crypto/evp/evp_enc.c::EVP_CipherInit_ex). 

\remark EVP_CIPHER::block_size используется при подготовке выходного буфера  
при зашифровании / расшифровании: размер выходного буфера на block_size
больше входного (см., например, функцию PKCS12_pbe_crypt() в модуле 
p12_decr.c). Поэтому, чтобы иметь возможность расширения шифртекста, 
block_size == 8 в режиме DWP и block_size == 16 в режиме KWP. 
Объявленная длина блока не влияет на гранулярность при обработке данных,
поскольку режимы объявлены с флагом EVP_CIPH_FLAG_CUSTOM_CIPHER.

\remark В режимах ECB, CBC среда отвечает за выравнивание данных на границу
блока и поэтому "кража блока", предусмотренная в СТБ 34.101.31,
не cрабатывает.

\remark Флаг EVP_CIPH_CUSTOM_IV указывает, что реализация сама отвечает
за размещение синхропосылки в контексте. Если флаг установлен и не 
установлен флаг EVP_CIPH_ALWAYS_CALL_INIT,
то в EVP_CipherInit_ex() входная синхропосылка игнорируется.

\remark В функциях evpBeltXXX_cipher() буферы in и out могут совпадать.
Поэтому память копируется с помощью memMove().

\remark Флаг EVP_CIPH_FLAG_CUSTOM_CIPHER указывает, что реализация
объявляет о размере выходных данных при зашифровании / расшифровании.
Объявляет двумя способами:
-	в EVP_CIPHER::do_cipher() определяет по размеру входного 
	буфера размер выходного и возвращает его;
-	если в EVP_CIPHER::do_cipher() передается нулевой входной буфер и 
	нулевая длина этого буфера, то возвращает размер дополнительного 
	выходного значения.

\remark Флаг EVP_CIPH_FLAG_DEFAULT_ASN1 указывает, что параметром
алгоритма является синхропосылка и эта синхропосылка кодируется 
стандартным образом, т.е. строкой октетов. При установке дополнительного
флага EVP_CIPH_WRAP_MODE считается, что параметров нет, и этот факт кодируется
типом NULL. При кодировании (декодировании) синхропосылка читается (записывается)
из (в) поле oiv контекста ctx.  

\warning Доступ к ctx->oiv открывает функция EVP_CIPHER_CTX_original_iv(). 
Доступ открывается только на чтение (возвращается const-указатель). 
Это недоработка OpenSSL, которую можно исправить, добавив функцию 
EVP_CIPHER_CTX_original_iv_noconst().

\remark Возможны вызовы init-функций как с нулевыми key, так и с нулевыми iv.

\remark Параметры алгоритмов режима ECB кодируется типом NULL. 
Для сравнения, если использовать флаг стандартного кодирования 
EVP_CIPH_FLAG_DEFAULT_ASN1, то параметры (гипотетическая синхропосылка) 
будут кодироваться пустой строкой октетов.

\remark В алгоритмах режима KWP заголовок ключа всегда является нулевым.
В принципе, заголовок можно сделать вариабельным, считая его 
параметром алгоритма. Пока необходимости в этом нет.

\remark При формировании контейнеров PKCS#5/8 в функции PKCS5_pbe2_set_iv() 
выполняются следующие действия:
1)	формируется случайная синхропосылка;
2)	если не установлен флаг EVP_CIPH_CUSTOM_IV и если установлен флаг 
	EVP_CIPH_CBС_MODE | EVP_CIPH_OFB_MODE | EVP_CIPH_CFB_MODE, 
	то синхропосылка записывается в EVP_CIPHER_CTX_original_iv(ctx),
	а затем переписывается в EVP_CIPHER_CTX_iv(ctx);
3)	если не установлен флаг EVP_CIPH_CUSTOM_IV и установлен флаг 
	EVP_CIPH_CTR_MODE, то синхропосылка напрямую записывается 
	в EVP_CIPHER_CTX_iv(ctx);
4)	синхропосылка попадает в init-функцию при установке флага 
	EVP_CIPH_ALWAYS_CALL_INIT.
Чтобы обеспечить обязательное попадание синхропосылки в 
EVP_CIPHER_CTX_original_iv(ctx) (с учетом возможного последующего 
ASN1-кодирования), алгоритмы режимов CBC и CFB объявляются без флага 
EVP_CIPH_CUSTOM_IV, а алгоритмы режимов CTR и DWP -- с флагами 
EVP_CIPH_CUSTOM_IV и EVP_CIPH_ALWAYS_CALL_INIT.

\remark Обращение к cleanup-функциям почему-то может выполняться два раза.
Поэтому вызов EVP_CIPHER_CTX_set_blob(ctx, 0) необходим.

\pre Среда проверяет указатели и размерности буферов, передаваемых
в функции интерфейсов EVP_CIPHER, EVP_MD.

\todo Разобраться с выравниванием на границу блока в режимах ECB, CBC.
*******************************************************************************
*/

/*
*******************************************************************************
Блобы

\remark При копировании блоба из одного контекста в другой проверяется, что
блоб-источник отличается от блоба-приемника. При совпадении состается
новый блоб-приемник. При отличии по возможности используется уже существующий
блоб. Впрочем совпадений скорее всего происходить не будет. И блоб-приемник
скорее всего будет пустым (нулевой указатель).
*******************************************************************************
*/

blob_t EVP_CIPHER_CTX_get_blob(const EVP_CIPHER_CTX* ctx)
{
	return (blob_t)EVP_CIPHER_CTX_get_cipher_data(ctx);
}

int EVP_CIPHER_CTX_set_blob(EVP_CIPHER_CTX* ctx, const blob_t blob)
{
	EVP_CIPHER_CTX_set_cipher_data(ctx, blob);
	return 1;
}

int EVP_CIPHER_CTX_copy_blob(EVP_CIPHER_CTX* to, const EVP_CIPHER_CTX* from)
{
	blob_t blob_from = EVP_CIPHER_CTX_get_blob(from);
	blob_t blob_to = EVP_CIPHER_CTX_get_blob(to);
	blob_to = blobCopy(blob_from == blob_to ? 0 : blob_to, blob_from);
	if (blob_from && !blob_to)
		return 0;
	return EVP_CIPHER_CTX_set_blob(to, blob_to);
}

/*
*******************************************************************************
Алгоритмы belt_ecb
*******************************************************************************
*/

const char OID_belt_ecb128[] = "1.2.112.0.2.0.34.101.31.11";
const char SN_belt_ecb128[] = "belt-ecb128";
const char LN_belt_ecb128[] = "belt-ecb128";

const char OID_belt_ecb192[] = "1.2.112.0.2.0.34.101.31.12";
const char SN_belt_ecb192[] = "belt-ecb192";
const char LN_belt_ecb192[] = "belt-ecb192";

const char OID_belt_ecb256[] = "1.2.112.0.2.0.34.101.31.13";
const char SN_belt_ecb256[] = "belt-ecb256";
const char LN_belt_ecb256[] = "belt-ecb256";

#define FLAGS_belt_ecb (EVP_CIPH_ECB_MODE |\
	EVP_CIPH_CTRL_INIT | EVP_CIPH_RAND_KEY | EVP_CIPH_CUSTOM_COPY)

static EVP_CIPHER* EVP_belt_ecb128;
const EVP_CIPHER* evpBeltECB128()
{
	return EVP_belt_ecb128;
}

static EVP_CIPHER* EVP_belt_ecb192;
const EVP_CIPHER* evpBeltECB192()
{
	return EVP_belt_ecb192;
}

static EVP_CIPHER* EVP_belt_ecb256;
const EVP_CIPHER* evpBeltECB256()
{
	return EVP_belt_ecb256;
}

static int evpBeltECB_init(EVP_CIPHER_CTX* ctx, const octet* key, 
	const octet* iv, int enc)
{
	blob_t state = EVP_CIPHER_CTX_get_blob(ctx);
	if (key)
		beltECBStart(state, key, EVP_CIPHER_CTX_key_length(ctx));
	return 1;
}

static int evpBeltECB_cipher(EVP_CIPHER_CTX* ctx, octet* out, const octet* in, 
	size_t inlen)
{
	blob_t state = EVP_CIPHER_CTX_get_blob(ctx);
	memMove(out, in, inlen);
	if (EVP_CIPHER_CTX_encrypting(ctx))
		beltECBStepE(out, inlen, state);
	else
		beltECBStepD(out, inlen, state);
	return 1;
}

static int evpBeltECB_cleanup(EVP_CIPHER_CTX *ctx)
{
	blobClose(EVP_CIPHER_CTX_get_blob(ctx));
	EVP_CIPHER_CTX_set_blob(ctx, 0);
	return 1;
}

static int evpBeltECB_set_asn1_params(EVP_CIPHER_CTX* ctx, ASN1_TYPE* params)
{
	params->type = V_ASN1_NULL;
	return 1;
}

static int evpBeltECB_get_asn1_params(EVP_CIPHER_CTX* ctx, ASN1_TYPE* params)
{
	return params->type == V_ASN1_NULL;
}

static int evpBeltECB_ctrl(EVP_CIPHER_CTX* ctx, int type, int p1, void* p2)
{
	switch (type)
	{
	case EVP_CTRL_INIT:
	{
		blob_t blob = blobCreate(beltECB_keep());
		if (blob && EVP_CIPHER_CTX_set_blob(ctx, blob))
			break;
		blobClose(blob);
		return 0;
	}
	case EVP_CTRL_RAND_KEY:
		if (!rngIsValid())
			return 0;
		rngStepR(p2, EVP_CIPHER_CTX_key_length(ctx), 0);
		break;
	case EVP_CTRL_COPY:
		if (!EVP_CIPHER_CTX_copy_blob((EVP_CIPHER_CTX*)p2, ctx))
			return 0;
		break;
	case EVP_CTRL_PBE_PRF_NID:
		*(int*)p2 = NID_belt_hmac;
		break;
	default:
		return -1;
	}
	return 1;
}

/*
*******************************************************************************
Алгоритмы belt_cbc
*******************************************************************************
*/

const char OID_belt_cbc128[] = "1.2.112.0.2.0.34.101.31.21";
const char SN_belt_cbc128[] = "belt-cbc128";
const char LN_belt_cbc128[] = "belt-cbc128";

const char OID_belt_cbc192[] = "1.2.112.0.2.0.34.101.31.22";
const char SN_belt_cbc192[] = "belt-cbc192";
const char LN_belt_cbc192[] = "belt-cbc192";

const char OID_belt_cbc256[] = "1.2.112.0.2.0.34.101.31.23";
const char SN_belt_cbc256[] = "belt-cbc256";
const char LN_belt_cbc256[] = "belt-cbc256";

#define FLAGS_belt_cbc (EVP_CIPH_CBC_MODE |\
	EVP_CIPH_CTRL_INIT | EVP_CIPH_RAND_KEY | EVP_CIPH_CUSTOM_COPY |\
	EVP_CIPH_FLAG_DEFAULT_ASN1)

static EVP_CIPHER* EVP_belt_cbc128;
const EVP_CIPHER* evpBeltCBC128()
{
	return EVP_belt_cbc128;
}

static EVP_CIPHER* EVP_belt_cbc192;
const EVP_CIPHER* evpBeltCBC192()
{
	return EVP_belt_cbc192;
}

static EVP_CIPHER* EVP_belt_cbc256;
const EVP_CIPHER* evpBeltCBC256()
{
	return EVP_belt_cbc256;
}

static int evpBeltCBC_init(EVP_CIPHER_CTX* ctx, const octet* key, 
	const octet* iv, int enc)
{
	blob_t state = EVP_CIPHER_CTX_get_blob(ctx);
	if (key)
	{
		beltCBCStart(state, key, EVP_CIPHER_CTX_key_length(ctx), 
			EVP_CIPHER_CTX_iv(ctx));
	}
	return 1;
}

static int evpBeltCBC_cipher(EVP_CIPHER_CTX* ctx, octet* out, const octet* in, 
	size_t inlen)
{
	blob_t state = EVP_CIPHER_CTX_get_blob(ctx);
	memMove(out, in, inlen);
	if (EVP_CIPHER_CTX_encrypting(ctx))
		beltCBCStepE(out, inlen, state);
	else
		beltCBCStepD(out, inlen, state);
	return 1;
}

static int evpBeltCBC_cleanup(EVP_CIPHER_CTX *ctx)
{
	blobClose(EVP_CIPHER_CTX_get_blob(ctx));
	EVP_CIPHER_CTX_set_blob(ctx, 0);
	return 1;
}

static int evpBeltCBC_ctrl(EVP_CIPHER_CTX* ctx, int type, int p1, void* p2)
{
	switch (type)
	{
	case EVP_CTRL_INIT:
	{
		blob_t blob = blobCreate(beltCBC_keep());
		if (blob && EVP_CIPHER_CTX_set_blob(ctx, blob))
			break;
		blobClose(blob);
		return 0;
	}
	case EVP_CTRL_RAND_KEY:
		if (!rngIsValid())
			return 0;
		rngStepR(p2, EVP_CIPHER_CTX_key_length(ctx), 0);
		break;
	case EVP_CTRL_COPY:
		if (!EVP_CIPHER_CTX_copy_blob((EVP_CIPHER_CTX*)p2, ctx))
			return 0;
		break;
	case EVP_CTRL_PBE_PRF_NID:
		*(int*)p2 = NID_belt_hmac;
		break;
	default:
		return -1;
	}
	return 1;
}

/*
*******************************************************************************
Алгоритмы belt_cfb
*******************************************************************************
*/

const char OID_belt_cfb128[] = "1.2.112.0.2.0.34.101.31.31";
const char SN_belt_cfb128[] = "belt-cfb128";
const char LN_belt_cfb128[] = "belt-cfb128";

const char OID_belt_cfb192[] = "1.2.112.0.2.0.34.101.31.32";
const char SN_belt_cfb192[] = "belt-cfb192";
const char LN_belt_cfb192[] = "belt-cfb192";

const char OID_belt_cfb256[] = "1.2.112.0.2.0.34.101.31.33";
const char SN_belt_cfb256[] = "belt-cfb256";
const char LN_belt_cfb256[] = "belt-cfb256";

#define FLAGS_belt_cfb (EVP_CIPH_CFB_MODE |\
	EVP_CIPH_CTRL_INIT | EVP_CIPH_RAND_KEY | EVP_CIPH_CUSTOM_COPY |\
	EVP_CIPH_FLAG_DEFAULT_ASN1)

static EVP_CIPHER* EVP_belt_cfb128;
const EVP_CIPHER* evpBeltCFB128()
{
	return EVP_belt_cfb128;
}

static EVP_CIPHER* EVP_belt_cfb192;
const EVP_CIPHER* evpBeltCFB192()
{
	return EVP_belt_cfb192;
}

static EVP_CIPHER* EVP_belt_cfb256;
const EVP_CIPHER* evpBeltCFB256()
{
	return EVP_belt_cfb256;
}

static int evpBeltCFB_init(EVP_CIPHER_CTX* ctx, const octet* key, 
	const octet* iv, int enc)
{
	blob_t state = EVP_CIPHER_CTX_get_blob(ctx);
	if (key)
	{
		beltCFBStart(state, key, EVP_CIPHER_CTX_key_length(ctx), 
			EVP_CIPHER_CTX_iv(ctx));
	}
	return 1;
}

static int evpBeltCFB_cipher(EVP_CIPHER_CTX* ctx, octet* out, const octet* in, 
	size_t inlen)
{
	blob_t state = EVP_CIPHER_CTX_get_blob(ctx);
	memMove(out, in, inlen);
	if (EVP_CIPHER_CTX_encrypting(ctx))
		beltCFBStepE(out, inlen, state);
	else
		beltCFBStepD(out, inlen, state);
	return 1;
}

static int evpBeltCFB_cleanup(EVP_CIPHER_CTX *ctx)
{
	blobClose(EVP_CIPHER_CTX_get_blob(ctx));
	EVP_CIPHER_CTX_set_blob(ctx, 0);
	return 1;
}

static int evpBeltCFB_ctrl(EVP_CIPHER_CTX* ctx, int type, int p1, void* p2)
{
	switch (type)
	{
	case EVP_CTRL_INIT:
	{
		blob_t blob = blobCreate(beltCFB_keep());
		if (blob && EVP_CIPHER_CTX_set_blob(ctx, blob))
			break;
		blobClose(blob);
		return 0;
	}
	case EVP_CTRL_RAND_KEY:
		if (!rngIsValid())
			return 0;
		rngStepR(p2, EVP_CIPHER_CTX_key_length(ctx), 0);
		break;
	case EVP_CTRL_COPY:
		if (!EVP_CIPHER_CTX_copy_blob((EVP_CIPHER_CTX*)p2, ctx))
			return 0;
		break;
	case EVP_CTRL_PBE_PRF_NID:
		*(int*)p2 = NID_belt_hmac;
		break;
	default:
		return -1;
	}
	return 1;
}

/*
*******************************************************************************
Алгоритмы belt_ctr

\remark Вместо флага EVP_CIPH_CTR_MODE используется флаг EVP_CIPH_OFB_MODE.
Замена позволяет использовать алгоритмы для защиты контейнеров PKCS#5/8
(см. обсуждение выше).
*******************************************************************************
*/

const char OID_belt_ctr128[] = "1.2.112.0.2.0.34.101.31.41";
const char SN_belt_ctr128[] = "belt-ctr128";
const char LN_belt_ctr128[] = "belt-ctr128";

const char OID_belt_ctr192[] = "1.2.112.0.2.0.34.101.31.42";
const char SN_belt_ctr192[] = "belt-ctr192";
const char LN_belt_ctr192[] = "belt-ctr192";

const char OID_belt_ctr256[] = "1.2.112.0.2.0.34.101.31.43";
const char SN_belt_ctr256[] = "belt-ctr256";
const char LN_belt_ctr256[] = "belt-ctr256";

#define FLAGS_belt_ctr (EVP_CIPH_CTR_MODE |\
	EVP_CIPH_CTRL_INIT | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_RAND_KEY |\
	EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV |\
	EVP_CIPH_FLAG_DEFAULT_ASN1)

static EVP_CIPHER* EVP_belt_ctr128;
const EVP_CIPHER* evpBeltCTR128()
{
	return EVP_belt_ctr128;
}

static EVP_CIPHER* EVP_belt_ctr192;
const EVP_CIPHER* evpBeltCTR192()
{
	return EVP_belt_ctr192;
}

static EVP_CIPHER* EVP_belt_ctr256;
const EVP_CIPHER* evpBeltCTR256()
{
	return EVP_belt_ctr256;
}

static int evpBeltCTR_init(EVP_CIPHER_CTX* ctx, const octet* key, 
	const octet* iv, int enc)
{
	blob_t state = EVP_CIPHER_CTX_get_blob(ctx);
	if (iv)
		memCopy((octet*)EVP_CIPHER_CTX_original_iv(ctx), iv, 16);
	if (key)
	{
		memCopy(EVP_CIPHER_CTX_iv_noconst(ctx), 
			EVP_CIPHER_CTX_original_iv(ctx), 16);
		beltCTRStart(state, key, EVP_CIPHER_CTX_key_length(ctx), 
			EVP_CIPHER_CTX_iv(ctx));
	}
	return 1;
}

static int evpBeltCTR_cipher(EVP_CIPHER_CTX* ctx, octet* out, const octet* in, 
	size_t inlen)
{
	blob_t state = EVP_CIPHER_CTX_get_blob(ctx);
	memMove(out, in, inlen);
	if (EVP_CIPHER_CTX_encrypting(ctx))
		beltCTRStepE(out, inlen, state);
	else
		beltCTRStepD(out, inlen, state);
	return 1;
}

static int evpBeltCTR_cleanup(EVP_CIPHER_CTX* ctx)
{
	blobClose(EVP_CIPHER_CTX_get_blob(ctx));
	EVP_CIPHER_CTX_set_blob(ctx, 0);
	return 1;
}

int evpBeltCTR_ctrl(EVP_CIPHER_CTX* ctx, int type, int p1, void* p2)
{
	switch (type)
	{
	case EVP_CTRL_INIT:
	{
		blob_t blob = blobCreate(beltCTR_keep());
		if (blob && EVP_CIPHER_CTX_set_blob(ctx, blob))
			break;
		blobClose(blob);
		return 0;
	}
	case EVP_CTRL_RAND_KEY:
		if (!rngIsValid())
			return 0;
		rngStepR(p2, EVP_CIPHER_CTX_key_length(ctx), 0);
		break;
	case EVP_CTRL_COPY:
		if (!EVP_CIPHER_CTX_copy_blob((EVP_CIPHER_CTX*)p2, ctx))
			return 0;
		break;
	case EVP_CTRL_PBE_PRF_NID:
		*(int*)p2 = NID_belt_hmac;
		break;
	default:
		return -1;
	}
	return 1;
}

/*
*******************************************************************************
Алгоритмы belt_dwp

\remark Известные схемы подключения AEAD-режимов предполагают использования
команд EVP_CTRL_AEAD_SET_TAG, EVP_CTRL_AEAD_GET_TAG для управления
имитовставками. Мы избрали другой путь: имитовставка указывается в последних
8 октетах обрабатываемых данных.

При снятии защиты последние 8 октетов очередного фрагмента данных не
обрабатываются криптографически, а кэшируются (поддерживается скользящее окно).
Решение о том, что эти октеты -- имитовставка принимается только в самом конце.
*******************************************************************************
*/

const char OID_belt_dwp128[] = "1.2.112.0.2.0.34.101.31.61";
const char SN_belt_dwp128[] = "belt-dwp128";
const char LN_belt_dwp128[] = "belt-dwp128";

const char OID_belt_dwp192[] = "1.2.112.0.2.0.34.101.31.62";
const char SN_belt_dwp192[] = "belt-dwp192";
const char LN_belt_dwp192[] = "belt-dwp192";

const char OID_belt_dwp256[] = "1.2.112.0.2.0.34.101.31.63";
const char SN_belt_dwp256[] = "belt-dwp256";
const char LN_belt_dwp256[] = "belt-dwp256";

#define FLAGS_belt_dwp (EVP_CIPH_FLAG_AEAD_CIPHER |\
	EVP_CIPH_CTRL_INIT | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_RAND_KEY |\
	EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV |\
	EVP_CIPH_FLAG_DEFAULT_ASN1)

static EVP_CIPHER* EVP_belt_dwp128;
const EVP_CIPHER* evpBeltDWP128()
{
	return EVP_belt_dwp128;
}

static EVP_CIPHER* EVP_belt_dwp192;
const EVP_CIPHER* evpBeltDWP192()
{
	return EVP_belt_dwp192;
}

static EVP_CIPHER* EVP_belt_dwp256;
const EVP_CIPHER* evpBeltDWP256()
{
	return EVP_belt_dwp256;
}

typedef struct belt_dwp_ctx
{
	octet block[8];			/*< блок данных (ловим имитовставку) */
	size_t block_len;		/*< длина блока */
	octet state[];			/*< состояние beltDWP */
} belt_dwp_ctx;


static int evpBeltDWP_init(EVP_CIPHER_CTX* ctx, const octet* key, 
	const octet* iv, int enc)
{
	belt_dwp_ctx* state = (belt_dwp_ctx*)EVP_CIPHER_CTX_get_blob(ctx);
	if (iv)
		memCopy((octet*)EVP_CIPHER_CTX_original_iv(ctx), iv, 16);
	if (key)
	{
		memCopy(EVP_CIPHER_CTX_iv_noconst(ctx),
			EVP_CIPHER_CTX_original_iv(ctx), 16);
		beltDWPStart(state->state, key, EVP_CIPHER_CTX_key_length(ctx),
			EVP_CIPHER_CTX_iv(ctx));
	}
	return 1;
}

static int evpBeltDWP_cipher(EVP_CIPHER_CTX* ctx, octet* out, const octet* in, 
	size_t inlen)
{
	belt_dwp_ctx* state = (belt_dwp_ctx*)EVP_CIPHER_CTX_get_blob(ctx);
	size_t outlen = 0;
	// завершение?
	if (!in)
	{
		if (EVP_CIPHER_CTX_encrypting(ctx))
		{
			// вычислить и отправить имитовставку
			beltDWPStepG(out, state->state);
			return 8;
		}
		// проверить имитовставку
		if (state->block_len != 8 ||
			!beltDWPStepV(state->block, state->state))
			return -1;
		return 0;
	}
	// открытые данные?
	if (!out)
	{
		beltDWPStepA(in, inlen, state->state);
		return 0;
	}
	// установить защиту
	if (EVP_CIPHER_CTX_encrypting(ctx))
	{
		// обработать критические данные
		memMove(out, in, inlen);
		beltDWPStepE(out, inlen, state->state);
		beltDWPStepA(out, inlen, state->state);
		outlen = inlen;
	}
	// снять защиту
	else
	{
		// есть что обрабатывать?
		if (state->block_len + inlen > 8)
		{
			// сколько всего обработать октетов
			size_t l = state->block_len + inlen - 8;
			// сколько обработать октетов block
			size_t lb = MIN2(state->block_len, l);
			// обработать октеты block
			memCopy(out, state->block, lb);
			beltDWPStepA(out, lb, state->state);
			beltDWPStepD(out, lb, state->state);
			out += lb, outlen += lb;
			// обработать октеты in
			memMove(out, in, l - lb);
			beltDWPStepA(out, l - lb, state->state);
			beltDWPStepD(out, l - lb, state->state);
			out += l - lb, outlen += l - lb;
			// обновить block
			if (lb < state->block_len)
			{
				memMove(state->block, state->block + lb,
					state->block_len - lb);
				memCopy(state->block + lb, in, 8 - state->block_len + lb);
			}
			else
				memCopy(state->block, in + inlen - 8, 8);
			state->block_len = 8;
		}
		// обрабатывать нечего, просто расширить блок
		else
		{
			memCopy(state->block + state->block_len, in, inlen);
			state->block_len += inlen;
		}
	}
	return (int)outlen;
}

static int evpBeltDWP_cleanup(EVP_CIPHER_CTX* ctx)
{
	blobClose(EVP_CIPHER_CTX_get_blob(ctx));
	EVP_CIPHER_CTX_set_blob(ctx, 0);
	return 1;
}

static int evpBeltDWP_ctrl(EVP_CIPHER_CTX* ctx, int type, int p1, void* p2)
{
	switch (type)
	{
	case EVP_CTRL_INIT:
	{
		blob_t blob = blobCreate(sizeof(belt_dwp_ctx) + beltDWP_keep());
		if (blob && EVP_CIPHER_CTX_set_blob(ctx, blob))
			break;
		blobClose(blob);
		return 0;
	}
	case EVP_CTRL_RAND_KEY:
		if (!rngIsValid())
			return 0;
		rngStepR(p2, EVP_CIPHER_CTX_key_length(ctx), 0);
		break;
	case EVP_CTRL_COPY:
		if (!EVP_CIPHER_CTX_copy_blob((EVP_CIPHER_CTX*)p2, ctx))
			return 0;
		break;
	case EVP_CTRL_PBE_PRF_NID:
		*(int*)p2 = NID_belt_hmac;
		break;
	default:
		return -1;
	}
	return 1;
}

/*
*******************************************************************************
Алгоритмы belt_kwp
*******************************************************************************
*/

const char OID_belt_kwp128[] = "1.2.112.0.2.0.34.101.31.71";
const char SN_belt_kwp128[] = "belt-kwp128";
const char LN_belt_kwp128[] = "belt-kwp128";

const char OID_belt_kwp192[] = "1.2.112.0.2.0.34.101.31.72";
const char SN_belt_kwp192[] = "belt-kwp192";
const char LN_belt_kwp192[] = "belt-kwp192";

const char OID_belt_kwp256[] = "1.2.112.0.2.0.34.101.31.73";
const char SN_belt_kwp256[] = "belt-kwp256";
const char LN_belt_kwp256[] = "belt-kwp256";

#define FLAGS_belt_kwp (EVP_CIPH_WRAP_MODE |\
	EVP_CIPH_CTRL_INIT | EVP_CIPH_RAND_KEY |\
	EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV |\
	EVP_CIPH_FLAG_DEFAULT_ASN1)

static EVP_CIPHER* EVP_belt_kwp128;
const EVP_CIPHER* evpBeltKWP128()
{
	return EVP_belt_kwp128;
}

static EVP_CIPHER* EVP_belt_kwp192;
const EVP_CIPHER* evpBeltKWP192()
{
	return EVP_belt_kwp192;
}

static EVP_CIPHER* EVP_belt_kwp256;
const EVP_CIPHER* evpBeltKWP256()
{
	return EVP_belt_kwp256;
}

typedef struct belt_kwp_ctx
{
	octet header[16];		/*< заголовок (после снятия защиты) */
	octet state[];			/*< состояние beltKWP */
} belt_kwp_ctx;

static int evpBeltKWP_init(EVP_CIPHER_CTX* ctx, const octet* key, 
	const octet* iv, int enc)
{
	belt_kwp_ctx* state = (belt_kwp_ctx*)EVP_CIPHER_CTX_get_blob(ctx);
	if (key)
		beltKWPStart(state->state, key, EVP_CIPHER_CTX_key_length(ctx));
	return 1;
}

static int evpBeltKWP_cipher(EVP_CIPHER_CTX* ctx, octet* out, const octet* in, 
	size_t inlen)
{
	belt_kwp_ctx* state = (belt_kwp_ctx*)EVP_CIPHER_CTX_get_blob(ctx);
	// завершение, возвратить число дополнительных октетов 
	if (!in)
		return 0;
	// установить защиту?
	if (EVP_CIPHER_CTX_encrypting(ctx))
	{
		if (inlen < 16)
			return -1;
		if (out)
		{
			memMove(out, in, inlen);
			memSetZero(out + inlen, 16);
			beltKWPStepE(out, inlen + 16, state->state);
		}
		inlen += 16;
	}
	// снять защиту
	else
	{
		if (inlen < 32)
			return -1;
		if (out)
		{
			memMove(out, in, inlen - 16);
			memCopy(state->header, in + inlen - 16, 16);
			beltKWPStepD2(out, state->header, inlen, state->state);
			if (!memIsZero(state->header, 16))
				return -1;
		}
		inlen -= 16;
	}
	return (int)inlen;
}

static int evpBeltKWP_cleanup(EVP_CIPHER_CTX* ctx)
{
	blobClose(EVP_CIPHER_CTX_get_blob(ctx));
	EVP_CIPHER_CTX_set_blob(ctx, 0);
	return 1;
}

static int evpBeltKWP_set_asn1_params(EVP_CIPHER_CTX* ctx,
	ASN1_TYPE* params)
{
	params->type = V_ASN1_NULL;
	return 1;
}

static int evpBeltKWP_get_asn1_params(EVP_CIPHER_CTX* ctx,
	ASN1_TYPE* params)
{
	return params->type == V_ASN1_NULL;
}

int evpBeltKWP_ctrl(EVP_CIPHER_CTX* ctx, int type, int p1, void* p2)
{
	switch (type)
	{
	case EVP_CTRL_INIT:
	{
		blob_t blob = blobCreate(sizeof(belt_kwp_ctx) + beltKWP_keep());
		if (blob && EVP_CIPHER_CTX_set_blob(ctx, blob))
		{
			EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
			break;
		}
		blobClose(blob);
		return 0;
	}
	case EVP_CTRL_RAND_KEY:
		if (!rngIsValid())
			return 0;
		rngStepR(p2, EVP_CIPHER_CTX_key_length(ctx), 0);
		break;
	case EVP_CTRL_COPY:
		if (!EVP_CIPHER_CTX_copy_blob((EVP_CIPHER_CTX*)p2, ctx))
			return 0;
		break;
	case EVP_CTRL_PBE_PRF_NID:
		*(int*)p2 = NID_belt_hmac;
		break;
	default:
		return -1;
	}
	return 1;
}

/*
*******************************************************************************
Регистрация алгоритмов
*******************************************************************************
*/

static int belt_cipher_nids[128];
static int belt_cipher_count;

#define BELT_CIPHER_REG(name, tmp)\
	(((tmp = NID_##name) != NID_undef) ?\
		belt_cipher_nids[belt_cipher_count++] = tmp :\
		(((tmp = OBJ_create(OID_##name, SN_##name, LN_##name)) > 0) ?\
			belt_cipher_nids[belt_cipher_count++] = tmp : NID_undef))

/*
*******************************************************************************
Перечисление алгоритмов
*******************************************************************************
*/

static ENGINE_CIPHERS_PTR prev_enum;

static int evpBeltCipher_enum(ENGINE* e, const EVP_CIPHER** cipher, 
	const int** nids, int nid)
{
	// возвратить таблицу идентификаторов?
	if (!cipher)
	{
		// объединить таблицы?
		if (prev_enum && prev_enum != evpBeltCipher_enum)
		{
			nid = prev_enum(e, cipher, nids, nid);
			if (nid <= 0)
				return 0;
			if (belt_cipher_count + nid >= (int)COUNT_OF(belt_cipher_nids))
				return 0;
			memCopy(belt_cipher_nids + belt_cipher_count, *nids, 
				nid * sizeof(int));
			*nids = belt_cipher_nids;
			return belt_cipher_count + nid;
		}
		// нет, просто отчитаться за себя
		*nids = belt_cipher_nids;
		return belt_cipher_count;
	}
	// обработать запрос (в порядке убывания приоритета)
	// .. длинный ключ
	if (nid == NID_belt_cfb256)
		*cipher = EVP_belt_cfb256;
	else if (nid == NID_belt_ctr256)
		*cipher = EVP_belt_ctr256;
	else if (nid == NID_belt_cbc256)
		*cipher = EVP_belt_cbc256;
	else if (nid == NID_belt_ecb256)
		*cipher = EVP_belt_ecb256;
	else if (nid == NID_belt_dwp256)
		*cipher = EVP_belt_dwp256;
	else if (nid == NID_belt_kwp256)
		*cipher = EVP_belt_kwp256;
	// .. короткий ключ
	else if (nid == NID_belt_cfb128)
		*cipher = EVP_belt_cfb128;
	else if (nid == NID_belt_ctr128)
		*cipher = EVP_belt_ctr128;
	else if (nid == NID_belt_cbc128)
		*cipher = EVP_belt_cbc128;
	else if (nid == NID_belt_ecb128)
		*cipher = EVP_belt_ecb128;
	else if (nid == NID_belt_dwp128)
		*cipher = EVP_belt_dwp128;
	else if (nid == NID_belt_kwp128)
		*cipher = EVP_belt_kwp128;
	// .. средний ключ
	else if (nid == NID_belt_cfb192)
		*cipher = EVP_belt_cfb192;
	else if (nid == NID_belt_ctr192)
		*cipher = EVP_belt_ctr192;
	else if (nid == NID_belt_cbc192)
		*cipher = EVP_belt_cbc192;
	else if (nid == NID_belt_ecb192)
		*cipher = EVP_belt_ecb192;
	else if (nid == NID_belt_dwp192)
		*cipher = EVP_belt_dwp192;
	else if (nid == NID_belt_kwp192)
		*cipher = EVP_belt_kwp192;
	else if (prev_enum && prev_enum != evpBeltCipher_enum)
		return prev_enum(e, cipher, nids, nid);
	else
		return 0;
	// ответ найден
	return 1;
}

/*
*******************************************************************************
Подключение / закрытие
*******************************************************************************
*/

#define BELT_CIPHER_DESCR(name, block_size, key_size, iv_len, flags,\
	init, cipher, cleanup, set_params, get_params, ctrl)\
	EVP_##name = EVP_CIPHER_meth_new(NID_##name, block_size, key_size);\
	if (EVP_##name == 0 ||\
		!EVP_CIPHER_meth_set_iv_length(EVP_##name, iv_len) ||\
		!EVP_CIPHER_meth_set_flags(EVP_##name, flags) ||\
		!EVP_CIPHER_meth_set_impl_ctx_size(EVP_##name, 0) ||\
		!EVP_CIPHER_meth_set_init(EVP_##name, init) ||\
		!EVP_CIPHER_meth_set_do_cipher(EVP_##name, cipher) ||\
		!EVP_CIPHER_meth_set_cleanup(EVP_##name, cleanup) ||\
		!EVP_CIPHER_meth_set_set_asn1_params(EVP_##name, set_params) ||\
		!EVP_CIPHER_meth_set_get_asn1_params(EVP_##name, get_params) ||\
		!EVP_CIPHER_meth_set_ctrl(EVP_##name, ctrl))\
		return 0;\


int evpBeltCipher_bind(ENGINE* e)
{
	int tmp;
	// зарегистрировать алгоритмы и получить nid'ы
	if (BELT_CIPHER_REG(belt_ecb128, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_ecb192, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_ecb256, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_cbc128, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_cbc192, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_cbc256, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_cfb128, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_cfb192, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_cfb256, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_ctr128, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_ctr192, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_ctr256, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_dwp128, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_dwp192, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_dwp256, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_kwp128, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_kwp192, tmp) == NID_undef ||
		BELT_CIPHER_REG(belt_kwp256, tmp) == NID_undef)
		return 0;
	// создать и настроить описатели
	BELT_CIPHER_DESCR(belt_ecb128, 16, 16, 0, FLAGS_belt_ecb,
		evpBeltECB_init, evpBeltECB_cipher, evpBeltECB_cleanup, 
		evpBeltECB_set_asn1_params, evpBeltECB_get_asn1_params, 
		evpBeltECB_ctrl);
	BELT_CIPHER_DESCR(belt_ecb192, 16, 24, 0, FLAGS_belt_ecb,
		evpBeltECB_init, evpBeltECB_cipher, evpBeltECB_cleanup, 
		evpBeltECB_set_asn1_params, evpBeltECB_get_asn1_params, 
		evpBeltECB_ctrl);
	BELT_CIPHER_DESCR(belt_ecb256, 16, 32, 0, FLAGS_belt_ecb,
		evpBeltECB_init, evpBeltECB_cipher, evpBeltECB_cleanup, 
		evpBeltECB_set_asn1_params, evpBeltECB_get_asn1_params, 
		evpBeltECB_ctrl);
	BELT_CIPHER_DESCR(belt_cbc128, 16, 16, 16, FLAGS_belt_cbc,
		evpBeltCBC_init, evpBeltCBC_cipher, evpBeltCBC_cleanup, 
		0, 0, evpBeltCBC_ctrl);
	BELT_CIPHER_DESCR(belt_cbc192, 16, 24, 16, FLAGS_belt_cbc,
		evpBeltCBC_init, evpBeltCBC_cipher, evpBeltCBC_cleanup, 
		0, 0, evpBeltCBC_ctrl);
	BELT_CIPHER_DESCR(belt_cbc256, 16, 32, 16, FLAGS_belt_cbc,
		evpBeltCBC_init, evpBeltCBC_cipher, evpBeltCBC_cleanup, 
		0, 0, evpBeltCBC_ctrl);
	BELT_CIPHER_DESCR(belt_cfb128, 1, 16, 16, FLAGS_belt_cfb,
		evpBeltCFB_init, evpBeltCFB_cipher, evpBeltCFB_cleanup, 
		0, 0, evpBeltCFB_ctrl);
	BELT_CIPHER_DESCR(belt_cfb192, 1, 24, 16, FLAGS_belt_cfb,
		evpBeltCFB_init, evpBeltCFB_cipher, evpBeltCFB_cleanup, 
		0, 0, evpBeltCFB_ctrl);
	BELT_CIPHER_DESCR(belt_cfb256, 1, 32, 16, FLAGS_belt_cfb,
		evpBeltCFB_init, evpBeltCFB_cipher, evpBeltCFB_cleanup, 
		0, 0, evpBeltCFB_ctrl);
	BELT_CIPHER_DESCR(belt_ctr128, 1, 16, 16, FLAGS_belt_ctr,
		evpBeltCTR_init, evpBeltCTR_cipher, evpBeltCTR_cleanup, 
		0, 0, evpBeltCTR_ctrl);
	BELT_CIPHER_DESCR(belt_ctr192, 1, 24, 16, FLAGS_belt_ctr,
		evpBeltCTR_init, evpBeltCTR_cipher, evpBeltCTR_cleanup, 
		0, 0, evpBeltCTR_ctrl);
	BELT_CIPHER_DESCR(belt_ctr256, 1, 32, 16, FLAGS_belt_ctr,
		evpBeltCTR_init, evpBeltCTR_cipher, evpBeltCTR_cleanup, 
		0, 0, evpBeltCTR_ctrl);
	BELT_CIPHER_DESCR(belt_dwp128, 8, 16, 16, FLAGS_belt_dwp,
		evpBeltDWP_init, evpBeltDWP_cipher, evpBeltDWP_cleanup, 
		0, 0, evpBeltDWP_ctrl);
	BELT_CIPHER_DESCR(belt_dwp192, 8, 24, 16, FLAGS_belt_dwp,
		evpBeltDWP_init, evpBeltDWP_cipher, evpBeltDWP_cleanup, 
		0, 0, evpBeltDWP_ctrl);
	BELT_CIPHER_DESCR(belt_dwp256, 8, 32, 16, FLAGS_belt_dwp,
		evpBeltDWP_init, evpBeltDWP_cipher, evpBeltDWP_cleanup, 
		0, 0, evpBeltDWP_ctrl);
	BELT_CIPHER_DESCR(belt_kwp128, 16, 16, 0, FLAGS_belt_kwp,
		evpBeltKWP_init, evpBeltKWP_cipher, evpBeltKWP_cleanup, 
		evpBeltKWP_set_asn1_params, evpBeltKWP_get_asn1_params, 
		evpBeltKWP_ctrl);
	BELT_CIPHER_DESCR(belt_kwp192, 16, 24, 0, FLAGS_belt_kwp,
		evpBeltKWP_init, evpBeltKWP_cipher, evpBeltKWP_cleanup, 
		evpBeltKWP_set_asn1_params, evpBeltKWP_get_asn1_params, 
		evpBeltKWP_ctrl);
	BELT_CIPHER_DESCR(belt_kwp256, 16, 32, 0, FLAGS_belt_kwp,
		evpBeltKWP_init, evpBeltKWP_cipher, evpBeltKWP_cleanup, 
		evpBeltKWP_set_asn1_params, evpBeltKWP_get_asn1_params, 
		evpBeltKWP_ctrl);
	// задать перечислитель
	prev_enum = ENGINE_get_ciphers(e);
	if (!ENGINE_set_ciphers(e, evpBeltCipher_enum))
		return 0;
	// зарегистрировать алгоритмы
	return ENGINE_register_ciphers(e) &&
		EVP_add_cipher(EVP_belt_ecb128) &&
		EVP_add_cipher(EVP_belt_ecb192) &&
		EVP_add_cipher(EVP_belt_ecb256) &&
		EVP_add_cipher(EVP_belt_cbc128) &&
		EVP_add_cipher(EVP_belt_cbc192) &&
		EVP_add_cipher(EVP_belt_cbc256) &&
		EVP_add_cipher(EVP_belt_cfb128) &&
		EVP_add_cipher(EVP_belt_cfb192) &&
		EVP_add_cipher(EVP_belt_cfb256) &&
		EVP_add_cipher(EVP_belt_ctr128) &&
		EVP_add_cipher(EVP_belt_ctr192) &&
		EVP_add_cipher(EVP_belt_ctr256) &&
		EVP_add_cipher(EVP_belt_dwp128) &&
		EVP_add_cipher(EVP_belt_dwp192) &&
		EVP_add_cipher(EVP_belt_dwp256) &&
		EVP_add_cipher(EVP_belt_kwp128) &&
		EVP_add_cipher(EVP_belt_kwp192) &&
		EVP_add_cipher(EVP_belt_kwp256);
}

void evpBeltCipher_finish()
{
	EVP_CIPHER_meth_free(EVP_belt_kwp256);
	EVP_belt_kwp256 = 0;
	EVP_CIPHER_meth_free(EVP_belt_kwp192);
	EVP_belt_kwp192 = 0;
	EVP_CIPHER_meth_free(EVP_belt_kwp128);
	EVP_belt_kwp128 = 0;
	EVP_CIPHER_meth_free(EVP_belt_dwp256);
	EVP_belt_dwp256 = 0;
	EVP_CIPHER_meth_free(EVP_belt_dwp192);
	EVP_belt_dwp192 = 0;
	EVP_CIPHER_meth_free(EVP_belt_dwp128);
	EVP_belt_dwp128 = 0;
	EVP_CIPHER_meth_free(EVP_belt_ctr256);
	EVP_belt_ctr256 = 0;
	EVP_CIPHER_meth_free(EVP_belt_ctr192);
	EVP_belt_ctr192 = 0;
	EVP_CIPHER_meth_free(EVP_belt_ctr128);
	EVP_belt_ctr128 = 0;
	EVP_CIPHER_meth_free(EVP_belt_cfb256);
	EVP_belt_cfb256 = 0;
	EVP_CIPHER_meth_free(EVP_belt_cfb192);
	EVP_belt_cfb192 = 0;
	EVP_CIPHER_meth_free(EVP_belt_cfb128);
	EVP_belt_cfb128 = 0;
	EVP_CIPHER_meth_free(EVP_belt_cbc256);
	EVP_belt_cbc256 = 0;
	EVP_CIPHER_meth_free(EVP_belt_cbc192);
	EVP_belt_cbc192 = 0;
	EVP_CIPHER_meth_free(EVP_belt_cbc128);
	EVP_belt_cbc128 = 0;
	EVP_CIPHER_meth_free(EVP_belt_ecb256);
	EVP_belt_ecb256 = 0;
	EVP_CIPHER_meth_free(EVP_belt_ecb192);
	EVP_belt_ecb192 = 0;
	EVP_CIPHER_meth_free(EVP_belt_ecb128);
	EVP_belt_ecb128 = 0;
}
