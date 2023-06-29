/*
*******************************************************************************
\file belt_tls.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Belt authenticated encryption for TLS
\created 2021.01.26
\version 2021.07.08
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
Реализация протокола TLS/Record в BTLS (СТБ 34.101.65)

1. Данные в TLS/Record разбиваются на фрагменты. Каждому фрагменту предшествует 
заголовок из полей [1]тип + [2]версия + [2]длина. Фрагменты нумеруются
последовательно от 0. Номер фрагмента [8]seq_num учитывается при его обработке.

2. При аутентифицированном шифровании с помощью belt-dwp 13-байтовый блок
  [1]тип + [2]версия + [2]длина + [8]seq_num
используется в качестве открытых (ассоциированных) данных.

3. При шифровании с помощью belt-ctr этот же блок сначала подвергается
имитозащите с помощью belt-mac, а затем записывается в конец фрагмента
и зашифровывается вместе с ним.

4. При обработке данных (открытых и критических) с помощью belt-dwp
используется синхропосылка 
  [fixed_iv_len = 8]fixed + [record_iv_len = 8]explicit.
Первая ее часть генерируется по завершению Handshake (это либо client_write_IV,
либо server_write_IV), вторая --- выбирается отправителем произвольно (без 
повторов) и передается в начале каждого фрагмента. В качестве второй части 
может использоваться номер seq_num, но это не обязательно.

5. При шифровании с помощью belt-ctr используется синхропосылка
  [8]seq_num + [8]zeros.
Синхропосылка не передается.
*******************************************************************************
*/

/*
*******************************************************************************
Алгоритмы belt-dwp-tls: belt-dwp для TLS

1. В OpenSSL параметр fixed_iv_len не предусмотрен. В общей ситуации
считается, что длина fixed-части синхропосылки совпадает с полной длиной
(см. вызов EVP_CIPHER_iv_length в ssl/t1_enc.c/tls1_setup_key_block).
Поэтому введен специальный алгоритм belt-dwp-tls (belt_dwpt в программах),
длина синхропосылки которого объявляется равной 8. Дополнительные 8 октетов
синхропосылки доопределяются в процессе обработки данных (в качестве
дополнительных октетов используется seq_num). Ключ belt-dwp-tls всегда
состоит из 32 октетов. 

\remark Для сравнения. В AES-GCM: fixed_iv_len = 4, record_iv_len = 8 [RFC5228].
Поддержка fixed_iv_len != iv_len для режимов GCM и CCM встроена в OpenSSL
(ssl/t1_enc.c/tls1_setup_key_block):
\code
	if (EVP_CIPHER_mode(c) == EVP_CIPH_GCM_MODE)
		k = EVP_GCM_TLS_FIXED_IV_LEN;
	else if (EVP_CIPHER_mode(c) == EVP_CIPH_CCM_MODE)
		k = EVP_CCM_TLS_FIXED_IV_LEN;
	else
		k = EVP_CIPHER_iv_length(c);
\endcode

\remark В ChaCha20: fixed_iv_len = 12, record_iv_len = 0 [RFC7905], при этом
seq_num всякий раз подмешивается к fixed-части синхропосылки. Поддержка
нестандартной длины fixed_iv_len не нужна.

2. Алгоритму belt-dwp-tls назначен нестандартный (технический) идентификатор
"1.2.112.0.2.0.34.101.31.67". Он может быть пересмотрен.

3. Обработка ctrl-кодов
  EVP_CTRL_GET_IVLEN, EVP_CTRL_AEAD_SET_IVLEN,
  EVP_CTRL_AEAD_SET_IV_FIXED, EVP_CTRL_AEAD_SET_TAG,
  EVP_CTRL_AEAD_GET_TAG
не является обязательной для интеграции TLS 1.2. Возможно она потребуется
для интеграции в TLS 1.3.
*******************************************************************************
*/

const char OID_belt_dwpt[] = "1.2.112.0.2.0.34.101.31.67";
const char SN_belt_dwpt[] = "belt-dwp-tls";
const char LN_belt_dwpt[] = "belt-dwp-tls";

#define FLAGS_belt_dwpt (EVP_CIPH_FLAG_AEAD_CIPHER |\
	EVP_CIPH_CTRL_INIT | EVP_CIPH_ALWAYS_CALL_INIT |\
	EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV)

static EVP_CIPHER* EVP_belt_dwpt;
const EVP_CIPHER* evpBeltDWPT()
{
	return EVP_belt_dwpt;
}

typedef struct belt_dwpt_ctx
{
	octet key[32];			/*< ключ */
	octet iv[16];			/*< синхропосылка */
	octet aad[16];			/*< заголовок TLS */
	size_t aad_len;			/*< длина заголовка TLS */
	octet tag[8];			/*< имитовставка */
	octet state[];			/*< состояние beltDWP */
} belt_dwpt_ctx;

static int evpBeltDWPT_init(EVP_CIPHER_CTX* ctx, const octet* key, 
	const octet* iv, int enc)
{
	belt_dwpt_ctx* state = (belt_dwpt_ctx*)EVP_CIPHER_CTX_get_blob(ctx);
	if (iv)
	{
		memCopy(state->iv, iv, 8);
		memSet(state->iv + 8, 0xFF, 8);
	}
	if (key)
	{
		memCopy(state->key, key, 32);
	}
	state->aad_len = 0;
	return 1;
}

static int evpBeltDWPT_cipher(EVP_CIPHER_CTX* ctx, octet* out,
	const octet* in, size_t len)
{
	belt_dwpt_ctx* state = (belt_dwpt_ctx*)EVP_CIPHER_CTX_get_blob(ctx);
	// выполняются соглашения libssl?
	if (out != in || !state->aad_len || len < 8 + 8)
		return -1;
	// обработать явную синхропосылку
	if (EVP_CIPHER_CTX_encrypting(ctx))
	{
		// записать синхропосылку в начало фрагмента
		memMove(out + 8, in, len);
		ASSERT(!memEq(state->aad, state->iv + 8, 8));
		memCopy(out, state->aad, 8);
		memCopy(state->iv + 8, state->aad, 8);
	}
	else
		// прочитать синхропосылку из начала фрагмента
		memCopy(state->iv + 8, out, 8);
	in += 8, out += 8, len -= 8;
	// запустить шифр
	beltDWPStart(state->state, state->key, 32, state->iv);
	// обработать открытые (ассоциированные) данные
	beltDWPStepI(state->aad, state->aad_len, state->state);
	// обработать фрагмент (без имитовставки)
	len -= 8;
	if (EVP_CIPHER_CTX_encrypting(ctx))
	{
		beltDWPStepE(out, len, state->state);
		beltDWPStepA(out, len, state->state);
		beltDWPStepG(out + len, state->state);
		len += 8 + 8;
	}
	else
	{
		beltDWPStepA(out, len, state->state);
		if (!beltDWPStepV(out + len, state->state))
		{
			memWipe(out, len);
			return -1;
		}
		beltDWPStepD(out, len, state->state);
		memMove(out - 8, out, len);
	}
	// число октетов, записанных в out
	return (int)len;
}

static int evpBeltDWPT_cleanup(EVP_CIPHER_CTX* ctx)
{
	blobClose(EVP_CIPHER_CTX_get_blob(ctx));
	EVP_CIPHER_CTX_set_blob(ctx, 0);
	return 1;
}

static int evpBeltDWPT_ctrl(EVP_CIPHER_CTX* ctx, int type, int p1, void* p2)
{
	belt_dwpt_ctx* state;
	switch (type)
	{
	case EVP_CTRL_INIT:
	{
		blob_t blob = blobCreate(sizeof(belt_dwpt_ctx) + beltDWP_keep());
		if (blob && EVP_CIPHER_CTX_set_blob(ctx, blob))
			break;
		blobClose(blob);
		return 0;
	}
	case EVP_CTRL_COPY:
		if (!EVP_CIPHER_CTX_copy_blob((EVP_CIPHER_CTX*)p2, ctx))
			return 0;
		break;
	case EVP_CTRL_GET_IVLEN:
		*(int*)p2 = 8;
		return 1;
	case EVP_CTRL_AEAD_SET_IVLEN:
		return p1 == 8 ? 1 : 0;
	case EVP_CTRL_AEAD_SET_IV_FIXED:
		if (p1 != 8)
			return 0;
		state = (belt_dwpt_ctx*)EVP_CIPHER_CTX_get_blob(ctx);
		memCopy(state->iv, p2, 8);
		return 1;
	case EVP_CTRL_AEAD_SET_TAG:
		if (p1 != 8)
			return 0;
		state = (belt_dwpt_ctx*)EVP_CIPHER_CTX_get_blob(ctx);
		memCopy(state->tag, p2, 8);
		return 1;
	case EVP_CTRL_AEAD_GET_TAG:
		if (p1 != 8)
			return 0;
		state = (belt_dwpt_ctx*)EVP_CIPHER_CTX_get_blob(ctx);
		memCopy(p2, state->tag, 8);
		return 1;
	case EVP_CTRL_AEAD_TLS1_AAD:
	{
		size_t len;
		state = (belt_dwpt_ctx*)EVP_CIPHER_CTX_get_blob(ctx);
		// сохранить заголовок фрагмента
		if (p1 != EVP_AEAD_TLS1_AAD_LEN)
			return 0;
		ASSERT(sizeof(state->aad) >= EVP_AEAD_TLS1_AAD_LEN);
		memCopy(state->aad, p2, state->aad_len = EVP_AEAD_TLS1_AAD_LEN);
		// определить длину фрагмента
		len = state->aad[state->aad_len - 2], len <<= 8;
		len += state->aad[state->aad_len - 1];
		// защита снимается?
		if (!EVP_CIPHER_CTX_encrypting(ctx))
		{
			// уменьшить длину фрагмента на длину явной
			// синхропосылки и имитовставки
			if (len < 8 + 8)
				return 0;
			len -= 8 + 8;
		}
		// сохранить уточненную длину
		state->aad[state->aad_len - 2] = (octet)(len >> 8);
		state->aad[state->aad_len - 1] = (octet)len;
		// возвратить поправку длины
		return 8 + 8;
	}
	default:
		return -1;
	}
	return 1;
}

/*
*******************************************************************************
Алгоритмы belt-ctr-tls: belt-ctr для TLS

1. Введен специальный алгоритм belt-ctr-tls (belt_ctrt в программах),
длина синхропосылки которого объявляется равной 0. При этом синхропосылка
продолжает состоять из 16 октетов, ее первая часть заполняется 8 октетами
seq_num, вторая часть нулевая. Ключ belt-ctr-tls всегда состоит из 32 октетов.

2. Счетчик seq_num передается с помощью управляющей команды
EVP_CTRL_AEAD_TLS1_AAD.

3. Алгоритм belt-ctr-tls дополнительно выполняет имитозащиту (перед
зашифрованием). Используется алгоритм belt-mac. Длина ключа имитозащиты --
32 октета. Ключ передается с помощью управляющей команды
EVP_CTRL_AEAD_SET_MAC_KEY. 

4. Алгоритму belt-ctr-tls назначен нестандартный (технический) идентификатор
"1.2.112.0.2.0.34.101.31.44". Он может быть пересмотрен.

5. Похожая схема подключения: crypto\evp\e_rc4_hmac_md5.c.
*******************************************************************************
*/

const char OID_belt_ctrt[] = "1.2.112.0.2.0.34.101.31.44";
const char SN_belt_ctrt[] = "belt-ctr-tls";
const char LN_belt_ctrt[] = "belt-ctr-tls";

#define FLAGS_belt_ctrt (EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_STREAM_CIPHER |\
	EVP_CIPH_CTRL_INIT | EVP_CIPH_ALWAYS_CALL_INIT)

static EVP_CIPHER* EVP_belt_ctrt;
const EVP_CIPHER* evpBeltCTRT()
{
	return EVP_belt_ctrt;
}

typedef struct belt_ctrt_ctx
{
	octet ekey[32];		/*< ключ шифрования */
	octet mkey[32];		/*< ключ имитозащиты */
	octet iv[16];		/*< синхропосылка */
	octet aad[16];		/*< заголовок TLS */
	size_t aad_len;		/*< длина заголовка TLS */
	octet state[];		/*< состояние beltCTR + beltMAC */
} belt_ctrt_ctx;

static int evpBeltCTRT_init(EVP_CIPHER_CTX* ctx, const octet* key,
	const octet* iv, int enc)
{
	belt_ctrt_ctx* state = (belt_ctrt_ctx*)EVP_CIPHER_CTX_get_blob(ctx);
	if (key)
		memCopy(state->ekey, key, 32);
	state->aad_len = 0;
	return 1;
}

static int evpBeltCTRT_cipher(EVP_CIPHER_CTX* ctx, octet* out,
	const octet* in, size_t len)
{
	belt_ctrt_ctx* state = (belt_ctrt_ctx*)EVP_CIPHER_CTX_get_blob(ctx);
	// выполняются соглашения libssl?
	if (out != in || !state->aad_len || len < 8)
		return -1;
	// запустить шифрование
	memCopy(state->iv, state->aad, 8);
	memSetZero(state->iv + 8, 8);
	beltCTRStart(state->state, state->ekey, 32, state->iv);
	// запустить имитозащиту
	beltMACStart(state->state + beltCTR_keep(), state->mkey, 32);
	beltMACStepA(state->aad, state->aad_len, state->state + beltCTR_keep());
	// обработать фрагмент (без имитовставки)
	if (EVP_CIPHER_CTX_encrypting(ctx))
	{
		beltMACStepA(out, len - 8, state->state + beltCTR_keep());
		beltMACStepG(out + len - 8, state->state + beltCTR_keep());
		beltCTRStepE(out, len, state->state);
	}
	else
	{
		beltCTRStepD(out, len, state->state);
		beltMACStepA(out, len - 8, state->state + beltCTR_keep());
		if (!beltMACStepV(out + len - 8, state->state + beltCTR_keep()))
		{
			memWipe(out, len);
			return -1;
		}
		len -= 8;
	}
	// число октетов, записанных в out
	return (int)len;
}

static int evpBeltCTRT_cleanup(EVP_CIPHER_CTX* ctx)
{
	blobClose(EVP_CIPHER_CTX_get_blob(ctx));
	EVP_CIPHER_CTX_set_blob(ctx, 0);
	return 1;
}

static int evpBeltCTRT_ctrl(EVP_CIPHER_CTX* ctx, int type, int p1, void* p2)
{
	belt_ctrt_ctx* state;
	switch (type)
	{
	case EVP_CTRL_INIT:
	{
		blob_t blob = blobCreate(sizeof(belt_ctrt_ctx) +
			beltCTR_keep() + beltMAC_keep());
		if (blob && EVP_CIPHER_CTX_set_blob(ctx, blob))
			break;
		blobClose(blob);
		return 0;
	}
	case EVP_CTRL_COPY:
		if (!EVP_CIPHER_CTX_copy_blob((EVP_CIPHER_CTX*)p2, ctx))
			return 0;
		break;
	case EVP_CTRL_AEAD_SET_MAC_KEY:
		if (p1 != 32)
			return 0;
		state = (belt_ctrt_ctx*)EVP_CIPHER_CTX_get_blob(ctx);
		memCopy(state->mkey, p2, 32);
		break;
	case EVP_CTRL_AEAD_TLS1_AAD:
	{
		size_t len;
		state = (belt_ctrt_ctx*)EVP_CIPHER_CTX_get_blob(ctx);
		// сохранить заголовок фрагмента
		if (p1 != EVP_AEAD_TLS1_AAD_LEN)
			return 0;
		ASSERT(sizeof(state->aad) >= EVP_AEAD_TLS1_AAD_LEN);
		memCopy(state->aad, p2, state->aad_len = EVP_AEAD_TLS1_AAD_LEN);
		// определить длину фрагмента
		len = state->aad[state->aad_len - 2], len <<= 8;
		len += state->aad[state->aad_len - 1];
		// защита снимается?
		if (!EVP_CIPHER_CTX_encrypting(ctx))
		{
			// уменьшить длину фрагмента на длину имитовставки
			if (len < 8)
				return 0;
			len -= 8;
		}
		// сохранить уточненную длину
		state->aad[state->aad_len - 2] = (octet)(len >> 8);
		state->aad[state->aad_len - 1] = (octet)len;
		// возвратить поправку длины
		return 8;
	}
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

static int belt_tls_nids[128];
static int belt_tls_count;

#define BELT_TLS_REG(name, tmp)\
	(((tmp = NID_##name) != NID_undef) ?\
		belt_tls_nids[belt_tls_count++] = tmp :\
		(((tmp = OBJ_create(OID_##name, SN_##name, LN_##name)) > 0) ?\
			belt_tls_nids[belt_tls_count++] = tmp : NID_undef))

/*
*******************************************************************************
Перечисление алгоритмов
*******************************************************************************
*/

static ENGINE_CIPHERS_PTR prev_enum;

static int evpBeltTLS_enum(ENGINE* e, const EVP_CIPHER** cipher, 
	const int** nids, int nid)
{
	// возвратить таблицу идентификаторов?
	if (!cipher)
	{
		// объединить таблицы?
		if (prev_enum && prev_enum != evpBeltTLS_enum)
		{
			nid = prev_enum(e, cipher, nids, nid);
			if (nid <= 0)
				return 0;
			if (belt_tls_count + nid >= (int)COUNT_OF(belt_tls_nids))
				return 0;
			memCopy(belt_tls_nids + belt_tls_count, *nids, 
				nid * sizeof(int));
			*nids = belt_tls_nids;
			return belt_tls_count + nid;
		}
		// нет, просто отчитаться за себя
		*nids = belt_tls_nids;
		return belt_tls_count;
	}
	// обработать запрос
	if (nid == NID_belt_dwpt)
		*cipher = EVP_belt_dwpt;
	else if (nid == NID_belt_ctrt)
		*cipher = EVP_belt_ctrt;
	else if (prev_enum && prev_enum != evpBeltTLS_enum)
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

#define BELT_TLS_DESCR(name, block_size, key_size, iv_len, flags,\
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


int evpBeltTLS_bind(ENGINE* e)
{
	int tmp;
	// зарегистрировать алгоритмы и получить nid'ы
	if (BELT_TLS_REG(belt_dwpt, tmp) == NID_undef)
		return 0;
	// создать и настроить описатели
	BELT_TLS_DESCR(belt_dwpt, 1, 32, 8, FLAGS_belt_dwpt,
		evpBeltDWPT_init, evpBeltDWPT_cipher, evpBeltDWPT_cleanup, 
		0, 0, evpBeltDWPT_ctrl);
	BELT_TLS_DESCR(belt_ctrt, 1, 32, 0, FLAGS_belt_ctrt,
		evpBeltCTRT_init, evpBeltCTRT_cipher, evpBeltCTRT_cleanup,
		0, 0, evpBeltCTRT_ctrl);
	// задать перечислитель
	prev_enum = ENGINE_get_ciphers(e);
	if (!ENGINE_set_ciphers(e, evpBeltTLS_enum))
		return 0;
	// зарегистрировать алгоритмы
	return ENGINE_register_ciphers(e) &&
		EVP_add_cipher(EVP_belt_dwpt) &&
		EVP_add_cipher(EVP_belt_ctrt);
}

void evpBeltTLS_finish()
{
	EVP_CIPHER_meth_free(EVP_belt_ctrt);
	EVP_belt_ctrt = 0;
	EVP_CIPHER_meth_free(EVP_belt_dwpt);
	EVP_belt_dwpt = 0;
}
