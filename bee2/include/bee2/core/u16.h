/*
*******************************************************************************
\file u16.h
\brief 16-bit words
\project bee2 [cryptographic library]
\created 2015.10.28
\version 2023.02.02
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

/*!
*******************************************************************************
\file u16.h
\brief 16-разрядные слова
*******************************************************************************
*/

#ifndef __BEE2_U16_H
#define __BEE2_U16_H

#include "bee2/defs.h"
#include "bee2/core/safe.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file u16.h

Реализованы операции над 16-разрядными словами и массивами таких слов.

\pre В функции передаются корректные буферы памяти.
*******************************************************************************
*/

#define U16_0 ((u16)0)
#define U16_1 ((u16)1)
#define U16_MAX ((u16)(U16_0 - U16_1))

/*!	\def u16RotHi
	\brief Циклический сдвиг u16-слова на d позиций в сторону старших разрядов
	\pre 0 < d < 16.
*/
#define u16RotHi(w, d)\
	((u16)((w) << (d) | (w) >> (16 - (d))))

/*!	\def u16RotLo
	\brief Циклический сдвиг u16-слова на d позиций в сторону младших разрядов
	\pre 0 < d < 16.
*/
#define u16RotLo(w, d)\
	((u16)((w) >> (d) | (w) << (16 - (d))))

/*!	\brief Реверс октетов

	Выполняется реверс октетов u16-слова w.
	\return Слово с переставленными октетами.
*/
u16 u16Rev(
	register u16 w		/*!< [in] слово */
);

/*!	\brief Реверс октетов массива слов

	Выполняется реверс октетов массива [count]buf из u16-слов.
*/
void u16Rev2(
	u16 buf[],			/*!< [in,out] приемник */
	size_t count		/*!< [in] число элементов */
);

/*!	\brief Вес

	Определяется число ненулевых битов в u16-слове w.
	\return Число ненулевых битов.
*/
size_t u16Weight(
	register u16 w		/*!< [in] слово */
);

/*!	\brief Четность

	Определяется сумма по модулю 2 битов u16-слова w.
	\return Сумма битов.
*/
bool_t u16Parity(
	register u16 w		/*!< [in] слово */
);

/*!	\brief Число младших нулевых битов

	Определяется длина серии из нулевых младших битов u16-слова w.
	\return Длина серии.
	\remark CTZ == Count of Trailing Zeros
	\safe Имеется ускоренная нерегулярная редакция.
	*/
size_t u16CTZ(
	register u16 w		/*!< [in] слово */
);

size_t SAFE(u16CTZ)(register u16 w);
size_t FAST(u16CTZ)(register u16 w);

/*!	\brief Число старших нулевых битов

	Определяется длина серии из нулевых старших битов машинного слова w.
	\return Длина серии.
	\remark CLZ == Count of Leading Zeros
	\safe Имеется ускоренная нерегулярная редакция.
*/
size_t u16CLZ(
	register u16 w		/*!< [in] слово */
);

size_t SAFE(u16CLZ)(register u16 w);
size_t FAST(u16CLZ)(register u16 w);

/*!	\brief Тасование битов

	Биты младшей половинки u16-слова w перемещаются в четные позиции,
	биты старшей половинки -- в нечетные.
	\return Слово с растасованными битами.
*/
u16 u16Shuffle(
	register u16 w		/*!< [in] слово */
);

/*!	\brief Обратное тасование битов

	Четные биты u16-слова w группируются в его младшей половинке,
	нечетные -- в старшей.
	\return Слово с группированными битами.
*/
u16 u16Deshuffle(
	register u16 w		/*!< [in] слово */
);

/*!	\brief Аддитивно-мультипликативное обращение

	Выполняется адиттивное и мультипликативное обращение
	u16-слова-как-числа w по модулю 2^16.
	\pre w -- нечетное.
	\return - w^{-1} \mod 2^16.
	\remark Вычисляемое слово используется в редукции Монтгомери.
*/
u16 u16NegInv(
	register u16 w		/*!< [in] слово */
);

/*!	\brief Загрузка из буфера памяти

	Буфер [count]src преобразуется в массив [(count + 1) / 2]dest слов u16.
*/
void u16From(
	u16 dest[],			/*!< [out] приемник */
	const void* src,	/*!< [in] источник */
	size_t count		/*!< [in] число октетов */
);

/*!	\brief Выгрузка в буфер памяти

	Буфер [count]dest формируется по массиву [(count + 1) / 2]src слов u16.
*/
void u16To(
	void* dest,			/*!< [out] приемник */
	size_t count,		/*!< [in] число октетов */
	const u16 src[]		/*!< [in] источник */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_U16_H */
