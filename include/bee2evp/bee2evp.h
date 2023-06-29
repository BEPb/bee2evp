/*
*******************************************************************************
\file bee2evp.h
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Definitions and interfaces
\created 2013.11.11
\version 2023.02.14
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

/*!
*******************************************************************************
\file bee2evp.h
\brief Определения и интерфейсы
*******************************************************************************
*/

#ifndef __BEE2EVP_H

#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file bee2evp.h

\section bee2evp-common Общие сведения

При разработке плагина были предприняты шаги, снижающие зависимость 
от потенциальных уязвимостей OpenSSL и "придвигающие" криптографическую 
границу как можно ближе к bee2. Во-первых, критические объекты алгоритмов 
и протоколов размещаются в блобах bee2. Во-вторых, для генерации ключей 
и других параметров вместо штатного генератора случайных чисел OpenSSL 
используется генератор bee2.
*******************************************************************************
*/

/*! \brief Короткое имя (идентификатор) плагина */
extern const char SN_bee2evp[];
/*! \brief Полное имя плагина */
extern const char LN_bee2evp[];

/*!
*******************************************************************************
\file bee2evp.h

\section bee2evp-belt Алгоритмы СТБ 34.101.31 (belt)

Используются названия алгоритмов, заданные в приложении Б к СТБ 34.101.31.

Каждый из алгоритмов шифрования и (или) имитозащиты можно использовать 
с ключами трех длин: 128, 192 и 256 битов. Алгоритмы с ключом 256 считаются 
стандартными. Длина ключа добавляется к названию алгоритмов.

Дополнительно реализован алгоритм belt-hmac, описанный в СТБ 34.101.47 
под именем hmac-hbelt.

Алгоритмы belt-dwpXXX подключаются как алгоритмы аутентифицированного
шифрования (AEAD). При установке защиты имитовставка добавляется к данным,
при снятии защиты -- проверяется. Дополнительные открытые (ассоциированные)
данные не используются.

Алгоритмы имитозащиты belt-macXXX и belt-hmac подключаются как методы ключа,
через структуру EVP_PKEY_METHOD. Форматы данных для этих методов задаются 
через структуру EVP_PKEY_ASN1_METHOD.

Для задания ключей belt-macXXX, belt-hmac следует использовать команду
EVP_PKEY_CTRL_SET_MAC_KEY. Можно использовать строковую команду hexkey,
параметром которой является ключ_заданный_шестнадцатеричной_строкой.

В реализациях алгоритмов шифрования / защиты данных / защиты ключей 
обрабатывается команда EVP_CTRL_PBE_PRF_NID. Возвращаемый ответ на команду 
означает, что для построения ключей алгоритмов по паролям должен использоваться
алгоритм PBKDF2 на основе belt-hmac. Связка PBKDF2 + belt-hmac описана 
в СТБ 34.101.45 (приложение Е).

Реализована TLS-редакция алгоритмов belt-dwp256 и TLS-редакция связки
belt-ctr256+belt-mac256. В TLS-редакциях учитываются особенности встраивания
шифров в криптонаборы TLS.

\remark Чтобы полностью выполнить рекомендации СТБ 34.101.45, нужно настроить 
параметры PBKDF2 в файле evp.h OpenSSL следующим образом:
\code
	#define PKCS5_SALT_LEN		8
	#define PKCS5_DEFAULT_ITER	10000
\endcode
Первый параметр -- длина синхропосылки (соли) в октетах, второй --- число 
итераций.
*******************************************************************************
*/

/* belt-ecb128 */
extern const char OID_belt_ecb128[];
extern const char SN_belt_ecb128[];
extern const char LN_belt_ecb128[];
#define NID_belt_ecb128 OBJ_sn2nid(SN_belt_ecb128)

/*!	\brief Описание алгоритмов belt-ecb128

	Возвращается описание алгоритмов belt-ecb128 (зашифрование и расшифрование
	в режиме простой замены на 128-битовом ключе).
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltECB128();

/* belt-ecb192 */
extern const char OID_belt_ecb192[];
extern const char SN_belt_ecb192[];
extern const char LN_belt_ecb192[];
#define NID_belt_ecb192 OBJ_sn2nid(SN_belt_ecb192)

/*!	\brief Описание алгоритмов belt-ecb192

	Возвращается описание алгоритмов belt-ecb192 (зашифрование и расшифрование
	в режиме простой замены на 192-битовом ключе).
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltECB192();

/* belt-ecb256 */
extern const char OID_belt_ecb256[];
extern const char SN_belt_ecb256[];
extern const char LN_belt_ecb256[];
#define NID_belt_ecb256 OBJ_sn2nid(SN_belt_ecb256)

/*!	\brief Описание алгоритмов belt-ecb256

	Возвращается описание алгоритмов belt-ecb256 (зашифрование и расшифрование
	в режиме простой замены на 256-битовом ключе).
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltECB256();

/* belt-cbc128 */
extern const char OID_belt_cbc128[];
extern const char SN_belt_cbc128[];
extern const char LN_belt_cbc128[];
#define NID_belt_cbc128 OBJ_sn2nid(SN_belt_cbc128)

/*!	\brief Описание алгоритмов belt-cbc128

	Возвращается описание алгоритмов belt-cbc128 (зашифрование и расшифрование
	в режиме сцепления блоков на 128-битовом ключе).
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltCBC128();

/* belt-cbc192 */
extern const char OID_belt_cbc192[];
extern const char SN_belt_cbc192[];
extern const char LN_belt_cbc192[];
#define NID_belt_cbc192 OBJ_sn2nid(SN_belt_cbc192)

/*!	\brief Описание алгоритмов belt-cbc192

	Возвращается описание алгоритмов belt-cbc192 (зашифрование и расшифрование
	в режиме сцепления блоков на 192-битовом ключе).
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltCBC192();

/* belt-cbc256 */
extern const char OID_belt_cbc256[];
extern const char SN_belt_cbc256[];
extern const char LN_belt_cbc256[];
#define NID_belt_cbc256 OBJ_sn2nid(SN_belt_cbc256)

/*!	\brief Описание алгоритмов belt-cbc256

	Возвращается описание алгоритмов belt-cbc256 (зашифрование и расшифрование
	в режиме сцепления блоков на 256-битовом ключе).
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltCBC256();

/* belt-cfb128 */
extern const char OID_belt_cfb128[];
extern const char SN_belt_cfb128[];
extern const char LN_belt_cfb128[];
#define NID_belt_cfb128 OBJ_sn2nid(SN_belt_cfb128)

/*!	\brief Описание алгоритмов belt-cfb128

	Возвращается описание алгоритмов belt-cfb128 (зашифрование и расшифрование
	в режиме гаммирования с обратной связью на 128-битовом ключе).
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltCFB128();

/* belt-cfb192 */
extern const char OID_belt_cfb192[];
extern const char SN_belt_cfb192[];
extern const char LN_belt_cfb192[];
#define NID_belt_cfb192 OBJ_sn2nid(SN_belt_cfb192)

/*!	\brief Описание алгоритмов belt-cfb192

	Возвращается описание алгоритмов belt-cfb192 (зашифрование и расшифрование
	в режиме гаммирования с обратной связью на 192-битовом ключе).
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltCFB192();

/* belt-cfb256 */
extern const char OID_belt_cfb256[];
extern const char SN_belt_cfb256[];
extern const char LN_belt_cfb256[];
#define NID_belt_cfb256 OBJ_sn2nid(SN_belt_cfb256)

/*!	\brief Описание алгоритмов belt-cfb256

	Возвращается описание алгоритмов belt-cfb256 (зашифрование и расшифрование
	в режиме гаммирования с обратной связью на 256-битовом ключе).
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltCFB256();

/* belt-ctr128 */
extern const char OID_belt_ctr128[];
extern const char SN_belt_ctr128[];
extern const char LN_belt_ctr128[];
#define NID_belt_ctr128 OBJ_sn2nid(SN_belt_ctr128)

/*!	\brief Описание алгоритмов belt-ctr128

	Возвращается описание алгоритмов belt-ctr128 (зашифрование и расшифрование
	в режиме счетчика на 128-битовом ключе).
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltCTR128();

/* belt-ctr192 */
extern const char OID_belt_ctr192[];
extern const char SN_belt_ctr192[];
extern const char LN_belt_ctr192[];
#define NID_belt_ctr192 OBJ_sn2nid(SN_belt_ctr192)

/*!	\brief Описание алгоритмов belt-ctr192

	Возвращается описание алгоритмов belt-ctr192 (зашифрование и расшифрование
	в режиме счетчика на 192-битовом ключе).
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltCTR192();

/* belt-ctr256 */
extern const char OID_belt_ctr256[];
extern const char SN_belt_ctr256[];
extern const char LN_belt_ctr256[];
#define NID_belt_ctr256 OBJ_sn2nid(SN_belt_ctr256)

/*!	\brief Описание алгоритмов belt-ctr256

	Возвращается описание алгоритмов belt-ctr256 (зашифрование и расшифрование
	в режиме счетчика на 256-битовом ключе).
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltCTR256();

/* belt-ctrt */
extern const char OID_belt_ctrt[];
extern const char SN_belt_ctrt[];
extern const char LN_belt_ctrt[];
#define NID_belt_ctrt OBJ_sn2nid(SN_belt_ctrt)

/*!	\brief Описание алгоритмов belt-ctrt

	Возвращается описание алгоритмов belt-ctrt (редакция belt-ctr для TLS).
	\return Описание алгоритмов.
*/
const EVP_CIPHER* evpBeltCTRT();

/* belt-mac128 */
extern const char OID_belt_mac128[];
extern const char SN_belt_mac128[];
extern const char LN_belt_mac128[];
#define NID_belt_mac128 OBJ_sn2nid(SN_belt_mac128)

/*!	\brief Описание методов belt-mac128

	Возвращается описание методов ключа belt-mac128 (имитозащита на 128-битовом 
	ключе).
	\return Описание методов ключа. 
*/
const EVP_PKEY_METHOD* evpBeltMAC128_pmeth();

/*!	\brief Описание форматов belt-mac128

	Возвращается описание форматов данных для методов ключа belt-mac128.
	\return Описание форматов. 
*/
const EVP_PKEY_ASN1_METHOD* evpBeltMAC128_ameth();

/* belt-mac192 */
extern const char OID_belt_mac192[];
extern const char SN_belt_mac192[];
extern const char LN_belt_mac192[];
#define NID_belt_mac192 OBJ_sn2nid(SN_belt_mac192)

/*!	\brief Описание методов belt-mac192

	Возвращается описание методов ключа belt-mac192 (имитозащита на 192-битовом 
	ключе).
	\return Описание методов ключа. 
*/
const EVP_PKEY_METHOD* evpBeltMAC192_pmeth();

/*!	\brief Описание форматов belt-mac192

	Возвращается описание форматов данных для методов ключа belt-mac192.
	\return Описание форматов. 
*/
const EVP_PKEY_ASN1_METHOD* evpBeltMAC192_ameth();

/* belt-mac256 */
extern const char OID_belt_mac256[];
extern const char SN_belt_mac256[];
extern const char LN_belt_mac256[];
#define NID_belt_mac256 OBJ_sn2nid(SN_belt_mac256)

/*!	\brief Описание методов belt-mac256

	Возвращается описание методов ключа belt-mac256 (имитозащита 
	на 256-битовом ключе).
	\return Описание методов ключа. 
*/
const EVP_PKEY_METHOD* evpBeltMAC256_pmeth();

/*!	\brief Описание форматов belt-mac256

	Возвращается описание форматов данных для методов ключа belt-mac256.
	\return Описание форматов. 
*/
const EVP_PKEY_ASN1_METHOD* evpBeltMAC256_ameth();

/* belt-dwp128 */
extern const char OID_belt_dwp128[];
extern const char SN_belt_dwp128[];
extern const char LN_belt_dwp128[];
#define NID_belt_dwp128 OBJ_sn2nid(SN_belt_dwp128)

/*!	\brief Описание алгоритмов belt-dwp128

	Возвращается описание алгоритмов belt-dwp128 (установка и снятие 
	защиты данных на 128-битовом ключе).
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltDWP128();

/* belt-dwp192 */
extern const char OID_belt_dwp192[];
extern const char SN_belt_dwp192[];
extern const char LN_belt_dwp192[];
#define NID_belt_dwp192 OBJ_sn2nid(SN_belt_dwp192)

/*!	\brief Описание алгоритмов belt-dwp192

	Возвращается описание алгоритмов belt-dwp192 (установка и снятие 
	защиты данных на 192-битовом ключе).
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltDWP192();

/* belt-dwp256 */
extern const char OID_belt_dwp256[];
extern const char SN_belt_dwp256[];
extern const char LN_belt_dwp256[];
#define NID_belt_dwp256 OBJ_sn2nid(SN_belt_dwp256)

/*!	\brief Описание алгоритмов belt-dwp256

	Возвращается описание алгоритмов belt-dwp256 (установка и снятие 
	защиты данных на 256-битовом ключе).
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltDWP256();

/* belt-dwpt */
extern const char OID_belt_dwpt[];
extern const char SN_belt_dwpt[];
extern const char LN_belt_dwpt[];
#define NID_belt_dwpt OBJ_sn2nid(SN_belt_dwpt)

/*!	\brief Описание алгоритмов belt-dwpt

	Возвращается описание алгоритмов belt-dwpt (редакция belt-dwp для TLS).
	\return Описание алгоритмов.
*/
const EVP_CIPHER* evpBeltDWPT();

/* belt-kwp128 */
extern const char OID_belt_kwp128[];
extern const char SN_belt_kwp128[];
extern const char LN_belt_kwp128[];
#define NID_belt_kwp128 OBJ_sn2nid(SN_belt_kwp128)

/*!	\brief Описание алгоритмов belt-kwp128

	Возвращается описание алгоритмов belt-kwp128 (установка и снятие 
	защиты ключей на 128-битовом ключе).
	\remark Используется нулевой заголовок защищаемого ключа.
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltKWP128();

/* belt-kwp192 */
extern const char OID_belt_kwp192[];
extern const char SN_belt_kwp192[];
extern const char LN_belt_kwp192[];
#define NID_belt_kwp192 OBJ_sn2nid(SN_belt_kwp192)

/*!	\brief Описание алгоритмов belt-kwp192

	Возвращается описание алгоритмов belt-kwp192 (установка и снятие 
	защиты ключей на 192-битовом ключе).
	\remark Используется нулевой заголовок защищаемого ключа.
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltKWP192();

/* belt-kwp256 */
extern const char OID_belt_kwp256[];
extern const char SN_belt_kwp256[];
extern const char LN_belt_kwp256[];
#define NID_belt_kwp256 OBJ_sn2nid(SN_belt_kwp256)

/*!	\brief Описание алгоритмов belt-kwp256

	Возвращается описание алгоритмов belt-kwp256 (установка и снятие 
	защиты ключей на 256-битовом ключе).
	\remark Используется нулевой заголовок защищаемого ключа.
	\return Описание алгоритмов. 
*/
const EVP_CIPHER* evpBeltKWP256();

/* belt-hash256 */
extern const char OID_belt_hash[];
extern const char SN_belt_hash[];
extern const char LN_belt_hash[];
#define NID_belt_hash OBJ_sn2nid(SN_belt_hash)

/*!	\brief Описание алгоритма belt-hash

	Возвращается описание алгоритма belt-hash (хэширование).
	\return Описание алгоритма. 
*/
const EVP_MD* evpBeltHash();

/* belt-hmac (hmac-hbelt) */
extern const char OID_belt_hmac[];
extern const char SN_belt_hmac[];
extern const char LN_belt_hmac[];
#define NID_belt_hmac OBJ_sn2nid(SN_belt_hmac)

/*!	\brief Описание методов belt-hmac

	Возвращается описание методов ключа belt-hmac
	(имитозащита по схеме HMAC на основе belt-hash).
	\return Описание методов ключа. 
*/
const EVP_PKEY_METHOD* evpBeltHMAC_pmeth();

/*!	\brief Описание форматов belt-hmac

	Возвращается описание форматов данных для методов ключа belt-hmac.
	\return Описание форматов. 
*/
const EVP_PKEY_ASN1_METHOD* evpBeltHMAC_ameth();

/*!
*******************************************************************************
\file bee2evp.h

\section bee2evp-bign Алгоритмы и другие объекты СТБ 34.101.45-2013 (bign)

Используются названия, заданные в приложениях к СТБ 34.101.45.

Алгоритмы ЭЦП и транспорта ключа подключаются как методы ключа bign,
через структуру EVP_PKEY_METHOD. Методы ключа дополнительно включают протокол
Диффи -- Хеллмана, определенный в СТБ 34.101.66 (приложение A).

Открытый ключ кодируется по правилам, описанным в приложении Д 
(типы DomainParameters, ECParameters), личный ключ -- по правилам, описанным 
в приложение Г к СТБ П 34.101.45 (тип PrivateKey).

Ключи сопровождаются атрибутами-флагами, которые задают опции кодирования, 
выработки ЭЦП, построения общего ключа. По умолчанию все флаги сброшены.

Флаги кодирования:
-	EVP_BIGN_PKEY_ENC_PARAMS_SPECIFIED: в типе DomainParameters
	даже стандартные параметры задаются в форме specified;
-	EVP_BIGN_PKEY_ENC_PARAMS_COFACTOR: в типе ECParameters
	задается необязательный компонент cofactor.

Флаг EVP_BIGN_PKEY_SIG_DETERMINISTIC задает использование алгоритма bign-genk
при генерации одноразового личного ключа во время выработки ЭЦП. При установке
флага одноразовый личный ключ строится по долговременному личному ключу 
и хэш-значению подписываемого сообщения.

Открытый ключ СТБ 34.101.45 может использоваться в протоколе Диффи -- Хеллмана
так, как это описано в СТБ 34.101.66 (приложение A). Реализованы два метода
построения секретного ключа по общему ключу Диффи -- Хеллмана
(эти методы принято обозначать аббревиатурой KDF, от key derivation function):
базовый и метод bake-kdf. Флаг EVP_BIGN_PKEY_KDF_BAKE задает выбор второго 
метода.

Базовый метод --- обе координаты ключа Диффи -- Хеллмана напрямую преобразуются 
в строку октетов. Этот метод используется в криптонаборах СТБ 34.101.65 
(приложение В). Максимальная длина строки -- l / 2, где l --- уровень 
стойкости.

Метод bake-kdf -- x-координата ключа Диффи --- Хеллмана, дополнительные 
открытые данные (сихнропосылка или user key material, UKM) и номер ключа 
обрабатываются алгоритмом bake-kdf, заданным в СТБ 34.101.66. Максимальная 
длина ключа алгоритма bake-kdf --- 32 октета. 

Для настройки алгоритмов и объектов bign можно использовать следующие 
строковые команды:
-	params --- долговременные параметры (bign-curve256v1, bign-curve384v1
	или bign-curve512v1);
-	enc_params --- опции кодирования стандартных долговременных
	параметров в DomainParameters (specified -- обязательное явное 
	кодирование, cofactor -- при явном кодировании указывается кофактор);
-	sig --- режим выработки ЭЦП (deterministic -- одноразовый личный ключ 
	вырабатывается с помощью алгоритма bign-genk);
-	kdf --- алгоритм построения ключа (bake -- алгоритм bake-kdf).

Алгоритм хэширования hash должен быть совместим с параметрами params 
(см. далее).

Строковые команды будут учитываться, например, при вызове
\code
	openssl genpkey -algorithm bign\
		-pkeyopt params:bign-curve256v1\
		-pkeyopt enc_params:specified\
		-pkeyopt enc_params:cofactor\
        -out privkey.pem

    openssl dgst\
        -sign privkey.pem\
        -pkeyopt sig:deterministic\
		-pkeyopt hash:sha256\
        file_to_sign
\endcode

Алгоритмы bign подключаются как методы ключа, через структуру EVP_PKEY_METHOD.
Форматы данных для этих методов задаются через структуру EVP_PKEY_ASN1_METHOD.

Алгоритмы ЭЦП работают в связке с алгоритмами хэширования. Разрешенные сочетания:
- алгоритмы bign уровня l = 128  вместе с belt-hash (bign-with-hspec);
- алгоритмы bign уровня l = 192  вместе с belt-bash384 (bign-with-bash384);
- алгоритмы bign уровня l = 256  вместе с belt-bash512 (bign-with-bash512);
- алгоритмы bign уровня l = 128  вместе с belt-bash256 (bign-with-bash256);
- алгоритмы bign уровня l  вместе с 2l-битовым хэш-алгоритмом, отличным 
  от предыдущих (bign-with-hspec).

Первые три сочетания являются основными, они используются по умолчанию.
Четвертое сочетание является экспериментальным. В нем поддерживаются любые 
алгоритмы с совместимыми размерностями (например, sha256, sha384, sha512).

Алгоритмы с идентификаторами bign-with-hbelt, bign-with-bashXXX не имеют 
параметров -- они описываются типом NULL. Параметром алгоритма bign-with-hspec 
является идентификатор связанного алгоритма хэширования.
*******************************************************************************
*/

/* bign-with-hspec */
extern const char OID_bign_with_hspec[];
extern const char SN_bign_with_hspec[];
extern const char LN_bign_with_hspec[];
#define NID_bign_with_hspec OBJ_sn2nid(SN_bign_with_hspec)

/* bign-with-hbelt */
extern const char OID_bign_with_hbelt[];
extern const char SN_bign_with_hbelt[];
extern const char LN_bign_with_hbelt[];
#define NID_bign_with_hbelt OBJ_sn2nid(SN_bign_with_hbelt)

/* bign-with-bash256 */
extern const char OID_bign_with_bash256[];
extern const char SN_bign_with_bash256[];
extern const char LN_bign_with_bash256[];
#define NID_bign_with_bash256 OBJ_sn2nid(SN_bign_with_bash256)

/* bign-with-bash384 */
extern const char OID_bign_with_bash384[];
extern const char SN_bign_with_bash384[];
extern const char LN_bign_with_bash384[];
#define NID_bign_with_bash384 OBJ_sn2nid(SN_bign_with_bash384)

/* bign-with-bash512 */
extern const char OID_bign_with_bash512[];
extern const char SN_bign_with_bash512[];
extern const char LN_bign_with_bash512[];
#define NID_bign_with_bash512 OBJ_sn2nid(SN_bign_with_bash512)

/* bign-keytransport */
extern const char OID_bign_keytransport[];
extern const char SN_bign_keytransport[];
extern const char LN_bign_keytransport[];
#define NID_bign_keytransport OBJ_sn2nid(SN_bign_keytransport)

/* bign-pubkey */
extern const char OID_bign_pubkey[];
extern const char SN_bign_pubkey[];
extern const char LN_bign_pubkey[];
#define NID_bign_pubkey OBJ_sn2nid(SN_bign_pubkey)

/* bign-curve256v1 */
extern const char OID_bign_curve256v1[];
extern const char SN_bign_curve256v1[];
extern const char LN_bign_curve256v1[];
#define NID_bign_curve256v1 OBJ_sn2nid(SN_bign_curve256v1)

/* bign-curve384v1 */
extern const char OID_bign_curve384v1[];
extern const char SN_bign_curve384v1[];
extern const char LN_bign_curve384v1[];
#define NID_bign_curve384v1 OBJ_sn2nid(SN_bign_curve384v1)

/* bign-curve512v1 */
extern const char OID_bign_curve512v1[];
extern const char SN_bign_curve512v1[];
extern const char LN_bign_curve512v1[];
#define NID_bign_curve512v1 OBJ_sn2nid(SN_bign_curve512v1)

/* bign-primefield */
extern const char OID_bign_primefield[];
extern const char SN_bign_primefield[];
extern const char LN_bign_primefield[];
#define NID_bign_primefield OBJ_sn2nid(SN_bign_primefield)

/*!	\brief Описание методов bign

	Возвращается описание методов ключа bign (ЭЦП и транспорт ключа).
	\return Описание методов ключа. 
*/
const EVP_PKEY_METHOD* evpBign_pmeth();

/*!	\brief Описание форматов bign

	Возвращается описание форматов данных для методов ключа bign.
	\return Описание форматов. 
*/
const EVP_PKEY_ASN1_METHOD* evpBign_ameth();

/*! \brief Флаг явного кодирования параметров */
#define EVP_BIGN_PKEY_ENC_PARAMS_SPECIFIED	1
/*! \brief Флаг кодирования кофактора */
#define EVP_BIGN_PKEY_ENC_PARAMS_COFACTOR	2
/*! \brief Флаг детерминированной выработки ЭЦП */
#define EVP_BIGN_PKEY_SIG_DETERMINISTIC		4
/*! \brief Флаг использования bake-kdf */
#define EVP_BIGN_PKEY_KDF_BAKE				8

/*!	\brief Установить параметры ключей bign 

	В ctx устанавливаются параметры params_nid ключей bign.
	\return Признак успеха (<= 0 в случае ошибки).
	\remark Проверяется совместимость params_nid с алгоритмом 
	хэширования hash_nid, установленным через evpBign_pkey_set_hash().
	При нарушении совместимости возвращается 0.
*/
int evpBign_pkey_set_params(
	EVP_PKEY_CTX* ctx,			/*!< [in,out] контекст ключа */
	int params_nid				/*!< [in] идентификатор параметров */
);

/*!	\brief Установить флаги кодирования bign

	В ctx устанавливаются флаги кодирования flags ключей параметров bign.
	\return Признак успеха (<= 0 в случае ошибки).
*/
int evpBign_pkey_set_enc_flags(
	EVP_PKEY_CTX* ctx,			/*!< [in,out] контекст ключей */
	u8 flags					/*!< [in] флаги */
);

/*!	\brief Сбросить флаги кодирования bign 

	В ctx сбрасываются флаги кодирования flags ключей и параметров bign.
	\return Признак успеха (<= 0 в случае ошибки).
*/
int evpBign_pkey_clr_enc_flags(
	EVP_PKEY_CTX* ctx,			/*!< [in,out] контекст ключей */
	u8 flags					/*!< [in] флаги */
);

/*!	\brief Установить флаги подписи bign

    В ctx устанавливаются флаги flags подписи bign.
    \return Признак успеха (<= 0 в случае ошибки).
*/
int evpBign_pkey_set_sig_flags(
    EVP_PKEY_CTX* ctx,			/*!< [in,out] контекст ключей */
    u8 flags					/*!< [in] флаги */
);

/*!	\brief Сбросить флаги подписи bign

    В ctx сбрасываются флаги flags подписи bign.
    \return Признак успеха (<= 0 в случае ошибки).
*/
int evpBign_pkey_clr_sig_flags(
    EVP_PKEY_CTX* ctx,			/*!< [in,out] контекст ключей */
    u8 flags					/*!< [in] флаги */
);

/*!	\brief Установить флаги механизма KDF для ключей bign

    В ctx устанавливаются флаги flags механизма KDF для ключей bign.
    \return Признак успеха (<= 0 в случае ошибки).
*/
int evpBign_pkey_set_kdf_flags(
    EVP_PKEY_CTX* ctx,			/*!< [in,out] контекст ключей */
    u8 flags					/*!< [in] флаги */
);

/*!	\brief Сбросить флаги механизма KDF для ключей bign

    В ctx сбрасываются флаги flags механизма KDF для ключей bign.
    \return Признак успеха (<= 0 в случае ошибки).
*/
int evpBign_pkey_clr_kdf_flags(
    EVP_PKEY_CTX* ctx,			/*!< [in,out] контекст ключей */
    u8 flags					/*!< [in] флаги */
);

/*!	\brief Установить данные для метода bake-kdf

	В ctx устанавливаются данные ukm для метода bake-kdf построения ключа.
	\expect{-2} В ctx установлен флаг EVP_BIGN_PKEY_KDF_BAKE.
	\return Признак успеха (<= 0 в случае ошибки).
*/
int evpBign_pkey_set_kdf_ukm(
	EVP_PKEY_CTX* ctx,			/*!< [in,out] контекст ключа */
	void* ukm,					/*!< [in] данные bake-kdf */
	size_t ukm_len				/*!< [in] длина ukm в октетах */
);

/*!	\brief Установить номер ключа для метода bake-kdf

	В ctx устанавливаются номер num для метода bake-kdf построения ключа.
	\expect{-2} В ctx установлен флаг EVP_BIGN_PKEY_KDF_BAKE.
	\return Признак успеха (<= 0 в случае ошибки).
*/
int evpBign_pkey_set_kdf_num(
	EVP_PKEY_CTX* ctx,			/*!< [in,out] контекст ключа */
	size_t num					/*!< [in] номер ключа */
);

/*!
*******************************************************************************
\file bee2evp.h

\section bee2evp-bash Алгоритмы СТБ 34.101.77-2016 (bash)

Реализованы алгоритмы семейства bash стандартных уровней стойкости 
l = 128, 192, 256. Используются названия алгоритмов, заданные в приложении Б 
к СТБ 34.101.77: к префиксу "bash" добавляется удвоенный уровень стойкости.
*******************************************************************************
*/

/* bash256 */
extern const char OID_bash256[];
extern const char SN_bash256[];
extern const char LN_bash256[];
#define NID_bash256 OBJ_sn2nid(SN_bash256)

/*!	\brief Описание алгоритма bash256

	Возвращается описание алгоритма bash256.
	\return Описание алгоритма. 
*/
const EVP_MD* evpBash256();

/* bash384 */
extern const char OID_bash384[];
extern const char SN_bash384[];
extern const char LN_bash384[];
#define NID_bash384 OBJ_sn2nid(SN_bash384)

/*!	\brief Описание алгоритма bash384

	Возвращается описание алгоритма bash384.
	\return Описание алгоритма. 
*/
const EVP_MD* evpBash384();

/* bash512 */
extern const char OID_bash512[];
extern const char SN_bash512[];
extern const char LN_bash512[];
#define NID_bash512 OBJ_sn2nid(SN_bash512)

/*!	\brief Описание алгоритма bash512

	Возвращается описание алгоритма bash512.
	\return Описание алгоритма. 
*/
const EVP_MD* evpBash512();

/*
*******************************************************************************
Загрузка в среде OpenSSL
*******************************************************************************
*/

/*!	\brief Загрузка плагина

	Загрузить плагин bee2evp в среде OpenSSL.
	\remark При компиляции без директивы OPENSSL_NO_DYNAMIC_ENGINE плагин 
	будет загружаться автоматически. Функцию вызывать не надо.
*/
void ENGINE_load_bee2evp();

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2EVP_H */
