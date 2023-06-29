/*
*******************************************************************************
\file btls.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Definitions for BTLS ciphersuites
\created 2021.01.12
\version 2021.06.09
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#ifndef _BTLS_H
#define _BTLS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/evp.h>
#include "../include/crypto/asn1.h"
#include "../crypto/objects/obj_dat.h"
#include "packet_local.h"

/*
*******************************************************************************
Идентификаторы
*******************************************************************************
*/

/* obj_mac.h */
#define NID_bign_pubkey 		(NUM_NID + 0)
#define NID_belt_hash 			(NUM_NID + 1)
#define NID_bash384				(NUM_NID + 2)
#define NID_bash512				(NUM_NID + 3)
#define NID_belt_dwpt			(NUM_NID + 4)
#define NID_belt_ctrt	 		(NUM_NID + 5)
#define NID_belt_mac256			(NUM_NID + 6)
#define NID_bign_with_hbelt 	(NUM_NID + 7)
#define NID_bign_with_bash384	(NUM_NID + 8)
#define NID_bign_with_bash512	(NUM_NID + 9)
#define NID_bign_curve256v1 	(NUM_NID + 10)
#define NID_bign_curve384v1 	(NUM_NID + 11)
#define NID_bign_curve512v1 	(NUM_NID + 12)
#define NID_kxbdhe				(NUM_NID + 13)
#define NID_kxbdht				(NUM_NID + 14)
#define NID_kxbdhe_psk			(NUM_NID + 15)
#define NID_kxbdht_psk			(NUM_NID + 16)

/* ssl_local.h */
#define SSL_kBDHE               0x00000200U
#define SSL_kBDHT				0x00000400U
#define SSL_kBDHEPSK			0x00000800U
#define SSL_kBDHTPSK			0x00001000U

#define SSL_aBIGN               0x00000100U

#define SSL_BELTCTR             0x00400000U
#define SSL_BELTDWP				0x00800000U

#define SSL_BELTMAC             0x00000400U
#define SSL_HBELT               0x00000800U
#define SSL_BASH384             0x00001000U
#define SSL_BASH512             0x00002000U

#define SSL_MD_BELTMAC_IDX 12
#define SSL_MD_HBELT_IDX 13
#define SSL_MD_BASH384_IDX 14
#define SSL_MD_BASH512_IDX 15

#define SSL_HANDSHAKE_MAC_BELTMAC SSL_MD_BELTMAC_IDX
#define SSL_HANDSHAKE_MAC_HBELT SSL_MD_HBELT_IDX

#define TLS1_PRF_HBELT (SSL_HANDSHAKE_MAC_HBELT << TLS1_PRF_DGST_SHIFT)

#define SSL_PKEY_BIGN 9

#define TLSEXT_SIGALG_bign_sign_128 0xe7e7
#define TLSEXT_SIGALG_bign_sign_192 0xe8e8
#define TLSEXT_SIGALG_bign_sign_256 0xe9e9

/* ssl.h */
#define SSL_TXT_kBDHE "kBDHE"
#define SSL_TXT_kBDHT "kBDHT"
#define SSL_TXT_kBDHEPSK "kBDHEPSK"
#define SSL_TXT_kBDHTPSK "kBDHTPSK"
#define SSL_TXT_aBIGN "aBIGN"
#define SSL_TXT_BELTCTR "BELTCTR"
#define SSL_TXT_BELTMAC "BELTMAC"
#define SSL_TXT_BELTDWP "BELTDWP"

/* tls1.h */
# define TLS_CT_BIGN_SIGN      231

# define BTLS1_RFC_DHE_BIGN_WITH_BELT_CTR_MAC_HBELT\
	"BTLS_DHE_BIGN_WITH_BELT_CTR_MAC_HBELT"
# define BTLS1_TXT_DHE_BIGN_WITH_BELT_CTR_MAC_HBELT\
	"DHE-BIGN-WITH-BELT-CTR-MAC-HBELT"
# define BTLS1_RFC_DHE_BIGN_WITH_BELT_DWP_HBELT\
	"BTLS_DHE_BIGN_WITH_BELT_DWP_HBELT"
# define BTLS1_TXT_DHE_BIGN_WITH_BELT_DWP_HBELT\
	"DHE-BIGN-WITH-BELT-DWP-HBELT"

# define BTLS1_RFC_DHT_BIGN_WITH_BELT_CTR_MAC_HBELT\
	"BTLS_DHT_BIGN_WITH_BELT_CTR_MAC_HBELT"
# define BTLS1_TXT_DHT_BIGN_WITH_BELT_CTR_MAC_HBELT\
	"DHT-BIGN-WITH-BELT-CTR-MAC-HBELT"
# define BTLS1_RFC_DHT_BIGN_WITH_BELT_DWP_HBELT\
	"BTLS_DHT_BIGN_WITH_BELT_DWP_HBELT"
# define BTLS1_TXT_DHT_BIGN_WITH_BELT_DWP_HBELT\
	"DHT-BIGN-WITH-BELT-DWP-HBELT"

# define BTLS1_RFC_DHE_PSK_BIGN_WITH_BELT_CTR_MAC_HBELT\
	"BTLS_DHE_PSK_BIGN_WITH_BELT_CTR_MAC_HBELT"
# define BTLS1_TXT_DHE_PSK_BIGN_WITH_BELT_CTR_MAC_HBELT\
	"DHE-PSK-BIGN-WITH-BELT-CTR-MAC-HBELT"
# define BTLS1_RFC_DHE_PSK_BIGN_WITH_BELT_DWP_HBELT\
	"BTLS_DHE_PSK_BIGN_WITH_BELT_DWP_HBELT"
# define BTLS1_TXT_DHE_PSK_BIGN_WITH_BELT_DWP_HBELT\
	"DHE-PSK-BIGN-WITH-BELT-DWP-HBELT"

# define BTLS1_RFC_DHT_PSK_BIGN_WITH_BELT_CTR_MAC_HBELT\
	"BTLS_DHT_PSK_BIGN_WITH_BELT_CTR_MAC_HBELT"
# define BTLS1_TXT_DHT_PSK_BIGN_WITH_BELT_CTR_MAC_HBELT\
	"DHT-PSK-BIGN-WITH-BELT-CTR-MAC-HBELT"
# define BTLS1_RFC_DHT_PSK_BIGN_WITH_BELT_DWP_HBELT\
	"BTLS_DHT_PSK_BIGN_WITH_BELT_DWP_HBELT"
# define BTLS1_TXT_DHT_PSK_BIGN_WITH_BELT_DWP_HBELT\
	"DHT-PSK-BIGN-WITH-BELT-DWP-HBELT"

/* t1_lib.c */

#define BIGN_CURVE256V1_ID 31 /* indices in TLS_GROUP_INFO nid_list[] */
#define BIGN_CURVE384V1_ID 32
#define BIGN_CURVE512V1_ID 33

/*
*******************************************************************************
Инициализация
*******************************************************************************
*/

int btls_init();

/*
*******************************************************************************
Механизм BIGN_DHE
*******************************************************************************
*/

int btls_construct_ske_bign_dhe(SSL* s, WPACKET* pkt);
int btls_process_ske_bign_dhe(SSL* s, PACKET* pkt, EVP_PKEY** pkey);

/*
*******************************************************************************
Механизм BIGN_DHT
*******************************************************************************
*/

int btls_construct_cke_bign_dht(SSL* s, WPACKET* pkt);
int btls_process_cke_bign_dht(SSL* s, PACKET* pkt);

/*
*******************************************************************************
Механизм BIGN_DHE_PSK
*******************************************************************************
*/
int btls_construct_ske_psk_bign_dhe(SSL* s, WPACKET* pkt);
int btls_process_ske_psk_bign_dhe(SSL* s, PACKET* pkt, EVP_PKEY** pkey);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BTLS_H */
