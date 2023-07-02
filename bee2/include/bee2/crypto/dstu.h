/*
*******************************************************************************
\file dstu.h
\brief DSTU 4145-2002 (Ukraine): digital signature algorithms
\project bee2 [cryptographic library]
\created 2012.04.27
\version 2023.02.02
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

/*!
*******************************************************************************
\file dstu.h
\brief Алгоритмы ДСТУ 4145-2002 (Украина)
*******************************************************************************
*/

#ifndef __BEE2_DSTU_H
#define __BEE2_DSTU_H

#include "bee2/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file dstu.h

Реализованы алгоритмы украинского стандарта ДСТУ 4145-2002.

Поля структуры долговременных параметров обозначаются также как в ДСТУ.

Максимальная размерность DSTU_SIZE соответствуют неприводимому многочлену
степени 509, указанному в ДСТУ.

Базовое поле f = GF(2^m) описывается массивом из 4 размерностей, задающих
полиномиальный или нормальный базисы. Первый элемент массива p[0] -- это 
степень расширения m поля f, элементы массива невозрастают:
p[0] >= p[1] >= p[2] >= p[3].

В полиномиальном базисе поле строится как кольцо вычетов GF(2) / (p(x)), 
где p(x) –- неприводимый трехчлен или пятичлен степени m. Многочлен p(x) 
определяется следующим образом: p(x) = x^p[0] + x^p[1] + x^p[2] + x^p[3] + 1.
При p[2] == 0 должно выполняться также p[3] == 0 и p(x) -- трехчлен.

Нормальный базис задается установкой p[0] = m, p[1] = p[2] = p[3] = 0. 
Операции в нормальном базисе не реализованы.

Степень m базового поля f определяет используемое число октетов
в массиве dstu_params::B: в этом массиве используется O_OF_B(m) октет. 
В буфере сжатой точки xpoint также используется O_OF_B(m) октет. 
В массиве dstu_params::P, в буферах открытого ключа pubkey и точки point 
используется 2 * O_OF_B(m) октетов.

В структуре dstu_params неиспользуемые октеты могут быть заданы 
произвольным образом.

Порядок группы точек dstu_params::n не превосходит 
	(2^m + 1 + 2 * 2^{m / 2}) / c,
где кофактор c >= 2. Таким образом, порядок dstu_params::n укладывается 
в O_OF_B(m) октетов и даже, может быть, в меньшее число октетов.

\remark Кофактор c >= 2, поскольку точка (0, \sqrt(dstu_params::B)) лежит 
на кривой и имеет порядок 2. 

\remark Для стандартных кривых, заданных в приложении Г, 
кофактор равняется 2 при dstu_params::A == 1 или 4 при dstu_params::A == 0. 

В буфере личного ключа privkey используется order_no октетов,
где order_no -- число значащих (без завершающих нулевых) октетов буфера 
[O_OF_B(m)]dstu_params::n, т. е. длина числа dstu_params::n в октетах.

\expect{ERR_BAD_INPUT} Все входные указатели корректны.

\safe todo
*******************************************************************************
*/

#define DSTU_SIZE O_OF_B(509)

/*
*******************************************************************************
Управление долговременными параметрами

\warning Параметры в нормальном базисе не поддержаны. 
*******************************************************************************
*/

/*! \brief Долговременные параметры dstu */
typedef struct
{
	u16 p[4];					/*!< описание базового поля */
	octet A;					/*!< коэффициент A (0 или 1) */
	octet B[DSTU_SIZE];			/*!< коэффициент B */
	octet n[DSTU_SIZE];			/*!< порядок группы точек */
	u32 c;						/*!< кофактор */
	octet P[2 * DSTU_SIZE];		/*!< базовая точка */
} dstu_params;

/*!	\brief Загрузка стандартных долговременных параметров

	В params загружаются стандартные долговременные параметры с именем name.
	Поддерживаются имена "1.2.804.2.1.1.1.1.3.1.1.1.2.0", ..., 
	"1.2.112.0.2.0.34.101.45.3.2.9". Это имена стандартных эллиптических кривых, 
	заданных в таблице Г.2. Первым именем названа кривая над GF(2^163),
	последним -- кривая над GF(2^431).
	\return ERR_OK, если параметры загружены, и код ошибки в противном случае.
	\remark Имена (идентификаторы) параметров взяты из файла 
	http://www.crypto.org.ua/Media/Default/patches/dstu101e.patch 
	(patch для OpenSSL).
	\remark ДСТУ не определяет стандартные базовые точки. Их надо генерировать
	дополнительно, например, с помощью функции dstuGenPoint().
*/
err_t dstuStdParams(
	dstu_params* params,		/*!< [out] стандартные параметры */
	const char* name			/*!< [in] имя параметров */
);

/*!	\brief Проверка долговременных параметров

	Проверяется корректность долговременных параметров params.
	\return ERR_OK, если параметры корректны, и код ошибки в противном
	случае.
	\remark Проверяется корректность в том числе и базовой точки P.
*/
err_t dstuValParams(
	const dstu_params* params	/*!< [in] параметры */
);

/*
*******************************************************************************
Управление точками ЭК
*******************************************************************************
*/

/*!	\brief Генерация точки

	Генерируется точка point эллиптической кривой, заданной долговременными 
	параметрами params.	При генерации используется генератор rng и его 
	состояние rng_state. Дополнительно проверяется, что порядок point 
	равняется params->n.
	\expect{ERR_BAD_PARAMS} Параметры params (кроме базовой точки P) корректны.
	\return ERR_OK, если точка сгенерирована, и код ошибки в противном
	случае.
	\remark Указатели point и params->P могут совпадать.
	\remark Реализован алгоритм из раздела 6.8 ДСТУ.
*/
err_t dstuGenPoint(
	octet point[],					/*!< [out] точка */
	const dstu_params* params,		/*!< [in] долговременные параметры */
	gen_i rng,						/*!< [in] генератор случайных чисел */
	void* rng_state					/*!< [in,out] состояние генератора */
);

/*!	\brief Проверка точки

	Проверяется, что точка point эллиптической кривой, заданной
	долговременными параметрами params, удовлетворяет требованиям ДСТУ.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\return ERR_OK, если точка корректна, и код ошибки в противном
	случае.
	\remark Реализован алгоритм из раздела 10.1 ДСТУ.
*/
err_t dstuValPoint(
	const dstu_params* params,		/*!< [in] долговременные параметры */
	const octet point[]				/*!< [in] проверяемая точка */
);

/*!	\brief Сжатие точки

	Точка point эллиптической кривой, заданной долговременными
	параметрами params, сжимается в точку xpoint.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\return ERR_OK, если точка сжата, и код ошибки в противном случае.
	\remark Реализован алгоритм из раздела 6.9 ДСТУ.
	\remark Буферы point и xpoint могут пересекаться.
*/
err_t dstuCompressPoint(
	octet xpoint[],					/*!< [out] сжатая точка */
	const dstu_params* params,		/*!< [in] параметры */
	const octet point[]				/*!< [in] сжимаемая точка */
);

/*!	\brief Восстановление точки

	Точка point эллиптической кривой, заданной долговременными
	параметрами params, восстанавливается из x-координаты (point->x).
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\return ERR_OK, если точка восстановлена, и код ошибки
	в противном случае.
	\remark Реализован алгоритм из раздела 6.10 ДСТУ.
	\remark Буферы point и xpoint могут пересекаться.
*/
err_t dstuRecoverPoint(
	octet point[],					/*!< [out] восстановленная точка */
	const dstu_params* params,		/*!< [in] параметры */
	const octet xpoint[]			/*!< [in] сжатая точка */
);

/*
*******************************************************************************
Управление ключами
*******************************************************************************
*/

/*!	\brief Генерация пары ключей

	Для заданных параметров params генерируются личный и открытый ключи
	privkey и pubkey ключи. При генерации используется генератор rng и его
	состояние rng_state.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_RNG} Генератор rng (с состоянием rng_state) корректен.
	\expect Используется криптографически стойкий генератор rng.
	\return ERR_OK, если ключи сгенерированы, и код ошибки
	в противном случае.
	\remark Реализован алгоритм из раздела 9 ДСТУ.
*/
err_t dstuGenKeypair(
	octet privkey[],				/*!< [out] личный ключ */
	octet pubkey[],					/*!< [out] открытый ключ */
	const dstu_params* params,		/*!< [in] долговременные параметры */
	gen_i rng,						/*!< [in] генератор случайных чисел */
	void* rng_state					/*!< [in,out] состояние генератора */
);

/*
*******************************************************************************
ЭЦП
*******************************************************************************
*/

/*!	\brief Выработка ЭЦП

	Вырабатывается подпись [ld / 8]sig сообщения с хэш-значением 
	[hash_len]hash. Подпись вырабатывается на личном ключе privkey. 
	При выработке ЭЦП 	используются долговременные параметры params 
	и генератор rng c состоянием rng_state.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_INPUT}:
	-	ld делится на 16;
	-	два вычета по модулю params->n укладываются в ld битов.
	\expect{ERR_BAD_PRIVKEY} Личный ключ privkey корректен.
	\expect{ERR_BAD_RNG} Генератор rng (с состоянием rng_state) корректен.
	\expect Используется криптографически стойкий генератор rng.
	\return ERR_OK, если подпись выработана, и код ошибки в противном
	случае.
*/
err_t dstuSign(
	octet sig[],					/*!< [out] подпись */
	const dstu_params* params,		/*!< [in] долговременные параметры */
	size_t ld,						/*!< [in] длина подписи в битах */
	const octet hash[],				/*!< [in] хэш-значение */
	size_t hash_len,				/*!< [in] длина хэш-значения в октетах */
	const octet privkey[],			/*!< [in] личный ключ */
	gen_i rng,						/*!< [in] генератор случайных чисел */
	void* rng_state					/*!< [in,out] состояние генератора */
);

/*!	\brief Проверка ЭЦП

	Проверяется подпись [ld / 8]sig сообщения с хэш-значением 
	[hash_len]hash. При проверке используются долговременные параметры 
	params и открытый ключ pubkey.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_PUBKEY} Открытый ключ pubkey корректен.
	\return ERR_OK, если подпись корректна, и код ошибки в противном
	случае.
*/
err_t dstuVerify(
	const dstu_params* params,		/*!< [in] долговременные параметры */
	size_t ld,						/*!< [in] длина подписи в битах */
	const octet hash[],				/*!< [in] хэш-значение */
	size_t hash_len,				/*!< [in] длина хэш-значения в октетах */
	const octet sig[],				/*!< [in] подпись */
	const octet pubkey[]			/*!< [in] открытый ключ */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif  /* __BEE2_DSTU_H */