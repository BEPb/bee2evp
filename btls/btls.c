/*
*******************************************************************************
\file btls.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief BTLS ciphersuites
\created 2021.01.11
\version 2021.06.09
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <crypto/evp.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "ssl_local.h"
#include "../crypto/evp/evp_local.h"
#include <openssl/rand.h>

#include "btls.h"

/*
*******************************************************************************
Алгоритм belt-mac256 для TLS

Для представления алгоритма belt-mac256 в связке BELT_CTR_MAC криптонаборов 
BTLS алгоритм belt-mac56 позиционируется ка алгоритм хэширования (MD). 
Это вынужденная мера, потому что альтернативный вариант -- AEAD -- будет 
означать, что при генерации ключевого материала ключи имитозащиты связки 
BELT_CTR_MAC не будут выделены как отдельные (см. функцию 
tls1_change_cipher_state() модуля t1_enc.c).

MD-интерфейс belt-mac256 объявлен, но не реализован. Функционал belt-mac256 
встроен в алгоритм belt-ctr-tls (TLS-версия belt-ctr). Это алгоритм объявлен 
с флагом AEAD и поэтому обращения к MD-интерфейсу belt-mac256 не используются 
(см. обработку флага EVP_CIPH_FLAG_AEAD_CIPHER в модуле t1_enc.c).

Регистрация belt-mac256 выполняется в модуле ssl_ciph.c и состоит в следующем:
- идентификатор NID_belt_mac256 добавляется в таблицу ssl_cipher_table_mac
  и связывается с флагом SSL_BELTMAC. Флаг SSL_BELTMAC устанавливается в слове 
  описания криптонабора для указания на использование belt-mac256;
- в таблице ssl_mac_pkey_id устанавливается ссылка на методы belt-mac256;
- в таблице ssl_mac_secret_size устанавливается длина ключа belt-mac256
  (32 октета).
*******************************************************************************
*/

const EVP_MD* evpMDBeltMac256()
{
    static const EVP_MD md_belt_mac256 = 
    {
        NID_belt_mac256,
    };
    return &md_belt_mac256;
}

/*
*******************************************************************************
Инициализация

\remark Для регистрации в статических массивах OpenSSL задействованные nid'ы 
должны быть статическими. Но OpenSSL не позволяет назначать nid'ы при 
регистрации oid'ов. С другой стороны, логика назначения вполне прозрачна: 
nid'ы назначаются последовательно, начиная с номера NUM_NID, указанного в 
crypto/objects/obj_dat.h. Мы учитываем эту логику, фактически предугадывая 
nid'ы.

\warning Регистрация nid'ов в btls_init() должна выполняться в том же порядке,
что и их объявление в btls.h.

\todo Покрыть переменную btls_inited  мьютексом.
*******************************************************************************
*/

static int btls_inited = 0;

int btls_init()
{
    if (btls_inited)
        return 1;
    if (OBJ_create("1.2.112.0.2.0.34.101.45.2.1", 
        "bign-pubkey", "bign-pubkey") != NID_bign_pubkey)
        return 0;
    if (OBJ_create("1.2.112.0.2.0.34.101.31.81", 
        "belt-hash", "belt-hash") != NID_belt_hash)
        return 0;
    if (OBJ_create("1.2.112.0.2.0.34.101.77.12", 
        "bash384", "bash384") != NID_bash384)
        return 0;
    if (OBJ_create("1.2.112.0.2.0.34.101.77.13", 
        "bash512", "bash512") != NID_bash512)
        return 0;
    if (OBJ_create("1.2.112.0.2.0.34.101.31.67",
        "belt-dwp-tls", "belt-dwp-tls") != NID_belt_dwpt)
        return 0;
    if (OBJ_create("1.2.112.0.2.0.34.101.31.44", 
        "belt-ctr-tls", "belt-ctr-tls") != NID_belt_ctrt)
        return 0;
    if (OBJ_create("1.2.112.0.2.0.34.101.31.53", 
        "belt-mac256", "belt-mac256") != NID_belt_mac256)
        return 0;
    if (OBJ_create("1.2.112.0.2.0.34.101.45.12", 
        "bign-with-hbelt", "bign-with-hbelt") != NID_bign_with_hbelt)
        return 0;
    if (OBJ_create("1.2.112.0.2.0.34.101.45.14", 
        "bign-with-bash384", "bign-with-bash384") != NID_bign_with_bash384)
        return 0;
    if (OBJ_create("1.2.112.0.2.0.34.101.45.15", 
        "bign-with-bash512", "bign-with-bash512") != NID_bign_with_bash512)
        return 0;
    if (OBJ_create("1.2.112.0.2.0.34.101.45.3.1", 
        "bign-curve256v1", "bign-curve256v1") != NID_bign_curve256v1)
        return 0;
    if (OBJ_create("1.2.112.0.2.0.34.101.45.3.2", 
        "bign-curve384v1", "bign-curve384v1") != NID_bign_curve384v1)
        return 0;
    if (OBJ_create("1.2.112.0.2.0.34.101.45.3.3", 
        "bign-curve512v1", "bign-curve512v1") != NID_bign_curve512v1)
        return 0;
    if (OBJ_new_nid(1) != NID_kxbdhe)
        return 0;
    if (OBJ_new_nid(1) != NID_kxbdht)
        return 0;
    if (OBJ_new_nid(1) != NID_kxbdhe_psk)
        return 0;
    if (OBJ_new_nid(1) != NID_kxbdht_psk)
        return 0;
    if (!EVP_add_digest(evpMDBeltMac256()))
        return 0;
    btls_inited++;
    return 1;
}

/*
*******************************************************************************
Механизм BIGN_DHE

Протокол:
 - S -> C: ServerKeyExchange[подписанный эфемерный ключ ДХ]
 - S <- C: ClientKeyExchange[эфемерный ключ ДХ]

\remark ДХ = "Диффи -- Хеллмана".

Ключи ДХ лежат на той же эллиптической кривой, что и открытый ключ сертификата 
сервера. Для сравнения, в механизме ECDHE используется кривая, не обязательно 
связанная с сертификатом. Номер кривой передается в ServerKeyExchange. 
Отличия BIGN_DHE от ECDHE незначительны, и мы пользуемся этим, минимально 
отступая от кода OpenSSL.

Подготовка SKE: btls_construct_ske_bign_dhe().
Обработка SKE: btls_process_ske_bign_dhe() [на основе tls_process_ske_ecdhe()]

Подготовка CKE: tls_construct_cke_ecdhe() [стандартная функция].
Обработка CKE: tls_process_cke_ecdhe() [стандартная функция].

Вызовы перечисленных функций встраиваются в модули ssl/statem/statem_srvr.c, 
ssl/statem/statem_clnt.c (см. обработку флага SSL_kBDHE).
*******************************************************************************
*/

int btls_construct_ske_bign_dhe(SSL* s, WPACKET* pkt)
{
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* pk = NULL;
    unsigned char* pk_val = NULL;
    size_t pk_len = 0;
    int  ret = 1;
    // получить ключ сертификата
    EVP_PKEY* pkey = s->cert->pkeys[SSL_PKEY_BIGN].privatekey;
    if (!pkey)
    {
        ret = 0;
        goto err;
    }
    // сгенерировать ключ ДХ
    if (s->s3->tmp.pkey != NULL ||
        (ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL ||
        !EVP_PKEY_keygen_init(ctx) || 
        !EVP_PKEY_keygen(ctx, &pk))
    {
        ret = 0;
        goto err;
    }
    // записать ключ ДХ
    if (!EVP_PKEY_get_raw_public_key(pk, NULL, &pk_len) ||
        !(pk_val = OPENSSL_malloc(pk_len)) ||
        !EVP_PKEY_get_raw_public_key(pk, pk_val, &pk_len) ||
        !WPACKET_sub_memcpy_u8(pkt, pk_val, pk_len))
    {
        ret = 0;
        goto err;
    }
    // запомнить ключ ДХ
    s->s3->tmp.pkey = pk;
    pk = NULL;
err:
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pk);
     if (pk_val) 
     {
         OPENSSL_cleanse(pk_val, pk_len);
         OPENSSL_free(pk_val);
     }
     if (ret == 0)
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
            SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
            ERR_R_INTERNAL_ERROR);
    return ret;
}

int btls_process_ske_bign_dhe(SSL* s, PACKET* pkt, EVP_PKEY** pkey)
{
    PACKET encoded_pt;
    // определить статический открытый ключ сервера
    if ((*pkey = X509_get0_pubkey(s->session->peer)) == 0)
        return 0;
    // загрузить параметры открытого ключа сервера
    if (s->s3->peer_tmp == 0 && (s->s3->peer_tmp = EVP_PKEY_new()) == 0)
            return 0;
    if (!EVP_PKEY_copy_parameters(s->s3->peer_tmp, *pkey))
        return 0;
    // загрузить эфемерный открытый ключ сервера
    if (!PACKET_get_length_prefixed_1(pkt, &encoded_pt)) 
        return 0;
    if (!EVP_PKEY_set1_tls_encodedpoint(s->s3->peer_tmp,
            PACKET_data(&encoded_pt),
            PACKET_remaining(&encoded_pt)))
        return 0;
    // завершить
    return 1;
}

/*
*******************************************************************************
Механизм BIGN_DHE_PSK

Протокол:
 - S -> C: ServerKeyExchange[psk_identity_hint, oid(curve), server_public]
 - S <- C: ClientKeyExchange[psk_identity, client_public]
   * psk_identity_hint --- подсказка по выбору psk;
   * oid(curve) --- идентификатор кривой, на которой будет выполняться 
     протокол ДХ;
   * server_public, client_public --- эфемерные ключи ДХ;
   * psk_identity --- идентификатор выбранного psk.

Подготовка SKE: btls_construct_ske_psk_bign_dhe().
Обработка SKE: btls_process_ske_psk_bign_dhe().

\remark В расширении supported_groups сообщения ClientHello клиент может
переслать серверу перечень подходящих кривых (см. RFC 8422). Сервер будет
использовать перечень для выбора рабочей кривой curve. В команде s_client
за отправку перечня отвечает параметр -curves. Если клиент не пересылает
перечень, то сервер использует кривую bign_curve256v1.

\warning Параметр -named_curve команды s_server, который позволяет навязать
серверу использование той или иной кривой, не должен использоваться.
Кривые Bign не включены в перечень стандартных именованных кривых, и поэтому
указание кривой Bign в качестве значения параметра приведет к ошибке.

\remark В расширении supported_groups кривые задаются целочисленными
идентификаторами. В модуле t1_lib.c идентификаторы представляют собой
индексы элементов массива стандартных кривых TLS_GROUP_INFO nid_list[].
Кривым bign назначены дополнительные идентификаторы
- BIGN_CURVE256V1_ID (31),
- BIGN_CURVE384V1_ID (32),
- BIGN_CURVE512V1_ID (33)
из резервного диапазона.

\warning В функции btls_construct_ske_psk_bign_dhe() вызывается ctrl-функция
ключа Bign с идентификатором EVP_PKEY_ALG_CTRL + 1. Эта функция должна 
устанавливать долговременные параметры Bign (см. код 
EVP_BIGN_PEKEY_CTRL_SET_PARAMS в bign_pmeth.c). Другими словами,
считается, что 
	EVP_BIGN_PEKEY_CTRL_SET_PARAMS = EVP_PKEY_ALG_CTRL + 1.

\remark Обработка psk_identity_hint выполняется в функции
tls_process_ske_psk_preamble до вызова btls_process_ske_psk_bign_dhe.

Подготовка CKE: tls_construct_cke_ecdhe() [стандартная функция].
Обработка CKE: tls_process_cke_ecdhe() [стандартная функция].

Вызовы перечисленных функций встраиваются в модули ssl/statem/statem_srvr.c, 
ssl/statem/statem_clnt.c (см. обработку флага SSL_kBDHEPSK).

\todo Является ли загрузка сертификата сервера ошибкой?
*******************************************************************************
*/

int btls_construct_ske_psk_bign_dhe(SSL* s, WPACKET* pkt)
{
    int ret = 0;
	size_t len;
	int curve_id;
	const TLS_GROUP_INFO* ginf;
	ASN1_OBJECT* obj;
	unsigned char* oid = NULL;
	int oid_len;
	EVP_PKEY_CTX* pctx = NULL;
    EVP_PKEY* pk = NULL;
	unsigned char* pk_val = NULL;
    size_t pk_len;
	// записать psk_identity_hint
    len = (s->cert->psk_identity_hint == NULL) ? 
		0 : strlen(s->cert->psk_identity_hint);
    if (len > PSK_MAX_IDENTITY_LEN || 
		!WPACKET_sub_memcpy_u16(pkt, s->cert->psk_identity_hint, len)) 
        goto err;
	// загружен сертификат сервера?
    if (s->s3->tmp.pkey != NULL) 
        goto err;
	// клиент не высылал расширение supported_groups?
	if (!s->ext.supportedgroups)
		// ...используем первую кривую bign
		curve_id = BIGN_CURVE256V1_ID;
	// ... определяем подходящую кривую по стандартной схеме
	else if (!(curve_id = tls1_shared_group(s, -2)))
		goto err;
	// определить oid(curve)
    if (!(ginf = tls1_group_id_lookup(curve_id)) ||
		!(obj = OBJ_nid2obj(ginf->nid)) || 
		!(oid_len = i2d_ASN1_OBJECT(obj, &oid)))
		goto err;
	// записать oid(curve)
	if (!WPACKET_sub_memcpy_u8(pkt, oid, oid_len))
		goto err;
	// генерировать эфемерный ключ
    pctx = EVP_PKEY_CTX_new_id(NID_bign_pubkey, NULL);
	if (!pctx || 
		EVP_PKEY_keygen_init(pctx) <= 0 ||
		EVP_PKEY_CTX_ctrl(pctx, -1, -1, EVP_PKEY_ALG_CTRL + 1, 
			ginf->nid, NULL) <= 0 ||
		EVP_PKEY_keygen(pctx, &pk) <= 0) 
        goto err;
	// записать эфемерный ключ
    if (!EVP_PKEY_get_raw_public_key(pk, NULL, &pk_len) ||
        !(pk_val = OPENSSL_malloc(pk_len)) ||
        !EVP_PKEY_get_raw_public_key(pk, pk_val, &pk_len) ||
        !WPACKET_sub_memcpy_u8(pkt, pk_val, pk_len))
        goto err;
	// сохранить эфемерный ключ в состоянии
    s->s3->tmp.pkey = pk;
    pk = NULL;
	ret = 1;
err:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pk);
    if (pk_val) 
	{
		OPENSSL_cleanse(pk_val, pk_len);
		OPENSSL_free(pk_val);
	}
	OPENSSL_free(oid);
    if (ret == 0)
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
            SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
            ERR_R_INTERNAL_ERROR);
    return ret;
}

int btls_process_ske_psk_bign_dhe(SSL* s, PACKET* pkt, EVP_PKEY** pkey)
{
	int ret = 0;
    unsigned int oid_len;
    const unsigned char* oid;
	ASN1_OBJECT* obj = NULL;
	int params_nid;
	EVP_PKEY* pk = NULL;
	EVP_PKEY_CTX* pctx = NULL;
    PACKET encoded_pt;
	// загрузить oid(curve) 
    if (!PACKET_get_1(pkt, &oid_len) ||
        !PACKET_get_bytes(pkt, &oid, (size_t)oid_len) ||
		!(obj = d2i_ASN1_OBJECT(NULL, &oid, oid_len)) ||
		(params_nid = OBJ_obj2nid(obj)) == NID_undef)
		goto err;
	// подготовиться к загрузке эфемерного открытого ключа сервера
    if (s->s3->peer_tmp == 0 && 
		(s->s3->peer_tmp = EVP_PKEY_new()) == 0)
		goto err;
	if (!(pctx = EVP_PKEY_CTX_new_id(NID_bign_pubkey, NULL)) ||
		EVP_PKEY_paramgen_init(pctx) <= 0 ||
		EVP_PKEY_CTX_ctrl(pctx, -1, -1, EVP_PKEY_ALG_CTRL + 1, 
			params_nid, NULL) <= 0 ||
	    EVP_PKEY_paramgen(pctx, &pk) <= 0 ||
		!EVP_PKEY_copy_parameters(s->s3->peer_tmp, pk))
		goto err;
    // загрузить эфемерный открытый ключ сервера
    if (!PACKET_get_length_prefixed_1(pkt, &encoded_pt) || 
		!EVP_PKEY_set1_tls_encodedpoint(s->s3->peer_tmp,
			PACKET_data(&encoded_pt), 
			PACKET_remaining(&encoded_pt)))
		goto err;
	ret = 1;
err:
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_free(pk);
	ASN1_OBJECT_free(obj);
    return ret;
}

/*
*******************************************************************************
Механизм BIGN_DHT

Протокол:
 - C -> S: ClientKeyExchange[token]
   * token = зашифрованный pre_master_secret

Ключ pre_master_secret состоит из 48 октетов. Он генерируется клиентом с 
помощью функции RAND_bytes().

Ключ pre_master_secret зашифровывается на открытом ключе сервера из сертификата 
сервера. Зашифрование выполняется с помощью алгоритма bign-keytransport. При 
зашифровании используется нулевой заголовок ключа. В результате зашифрования 
получается токен ключа. 

Подготовка CKE: btls_construct_cke_bign_dht().
Обработка CKE: btls_process_сke_bign_dht().

Вызовы перечисленных функций встраиваются в модули ssl/statem/statem_srvr.c,
ssl/statem/statem_clnt.c (см. обработку флага SSL_kBDHT).

todo: Клиент должен проверить установку флага keyEncipherment в расширении 
KeyUsage сертификата сервера.

todo: Можно ли взять под контроль генерацию pre_master_secret клиентом?
*******************************************************************************
*/

int btls_construct_cke_bign_dht(SSL* s, WPACKET* pkt){
    unsigned char* pms = NULL;
    size_t pms_len = 48;
    EVP_PKEY_CTX* pkey_ctx = NULL;
    X509* peer_cert;
    unsigned char* token = NULL;
    size_t token_len = 0;
    int ret = 0;
    // подготовка pms = pre_master_secret
    pms = OPENSSL_malloc(pms_len);
    if (!pms)
        goto err;
    if (!RAND_bytes(pms, (int)pms_len))
        goto err;
    peer_cert = s->session->peer;
    if (!peer_cert)
        goto err;
    // определить server_pubkey
    pkey_ctx = EVP_PKEY_CTX_new(X509_get0_pubkey(peer_cert), NULL);
    // token <- bign_keytransport(pms, server_pubkey)
    if (!EVP_PKEY_encrypt_init(pkey_ctx))
        goto err;
    if (!EVP_PKEY_encrypt(pkey_ctx, NULL, &token_len, pms, pms_len))
        goto err;
    token = OPENSSL_malloc(token_len);
    if (!token)
        goto err;
    if (!EVP_PKEY_encrypt(pkey_ctx, token, &token_len, pms, pms_len))
        goto err;
    if (!WPACKET_sub_memcpy_u8(pkt, token, token_len))
        goto err;
    // сохранить pms
    s->s3->tmp.pms = pms;
    s->s3->tmp.pmslen = pms_len;
    pms = NULL;
    ret = 1;
err:
    if (pms)
        OPENSSL_free(pms);
    if (token)
        OPENSSL_free(token);
    if (pkey_ctx)
        EVP_PKEY_CTX_free(pkey_ctx);
    if (ret == 0)
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
            SSL_F_TLS_CONSTRUCT_CLIENT_KEY_EXCHANGE,
            ERR_R_INTERNAL_ERROR);
    return ret;
}

int btls_process_cke_bign_dht(SSL* s, PACKET* pkt)
{
	int ret = 0;
	EVP_PKEY* pk = NULL;
    EVP_PKEY_CTX* pkey_ctx = NULL;
    unsigned char* pms = NULL;
    size_t pms_len = 0;
    const unsigned char* token;
    unsigned int token_len;
    // подготовить личный ключ
    pk = s->cert->pkeys[SSL_PKEY_BIGN].privatekey;
    if (pk == NULL)
        goto err;
    pkey_ctx = EVP_PKEY_CTX_new(pk, NULL);
    if (pkey_ctx == NULL)
        goto err;
    if (!EVP_PKEY_decrypt_init(pkey_ctx))
        goto err;
    // извлечь токен ключа
    if (!PACKET_get_1(pkt, &token_len) || 
        !PACKET_get_bytes(pkt, &token, token_len) || 
        PACKET_remaining(pkt) != 0)
        goto err;
    // снять защиту с токена
    if (!EVP_PKEY_decrypt(pkey_ctx, NULL, &pms_len, token, token_len) ||
        pms_len != 48)
        goto err;
    pms = (unsigned char*)OPENSSL_malloc(pms_len);
    if (!EVP_PKEY_decrypt(pkey_ctx, pms, &pms_len, token, token_len))
        goto err;
    if (!ssl_generate_master_secret(s, pms, pms_len, 0))
        goto err;
    ret = 1;
err:
    if (pkey_ctx != NULL)
        EVP_PKEY_CTX_free(pkey_ctx);
    if (pms != NULL)
        OPENSSL_free(pms);
    if (ret == 0)
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
            SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
            ERR_R_INTERNAL_ERROR);
    return ret;
}

/*
*******************************************************************************
Механизм BIGN_DHT_PSK

Протокол:
 - S -> C: ServerKeyExchange[psk_identity_hint]
 - C -> S: ClientKeyExchange[psk_identity, token]
   * token = зашифрованный pre_master_secret

Ключ pre_master_secret имеет вид:
  len(other_secret) + other_secret + len(psk) + psk,
где other_secret -- секрет из 48 октетов.

Зашифрование pre_master_secret выполняется по правилам механизма BIGN_DHT.

Подготовка SKE: tls_construct_server_key_exchange() [стандартная функция].
Обработка SKE: tls_process_key_exchange() [стандартная функция].

Подготовка CKE: btls_construct_cke_bign_dht().
Обработка CKE: btls_process_сke_bign_dht().

Вызовы последних функций встраиваются в модули ssl/statem/statem_srvr.c,
ssl/statem/statem_clnt.c (см. обработку флага SSL_kBDHTPSK).

todo: Клиент должен проверить установку флага keyEncipherment в расширении
KeyUsage сертификата сервера.

todo: Можно ли взять под контроль генерацию other_secret клиентом?
*******************************************************************************
*/
