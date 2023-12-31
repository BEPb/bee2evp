/*
*******************************************************************************
\file zm.h
\brief Quotient rings of integers modulo m
\project bee2 [cryptographic library]
\created 2013.09.14
\version 2023.02.02
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

/*!
*******************************************************************************
\file zm.h
\brief Кольца вычетов целых чисел
*******************************************************************************
*/

#ifndef __ZM_H

#include "bee2/math/qr.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file zm.h

Реализованы операции в кольце вычетов Zm = Z / (mod), где mod -- произвольное 
натуральное число.

Элементы кольца кодируются строками из no октетов и задаются массивами из
W_OF_O(no) машинных слов, где no -- длина mod в октетах. При кодировании 
используются порядок "от младших к старшим". Перечисленные соглашения можно 
учитывать при планировании работы с кольцом.

Для редукции по модулю mod используются функции, объявленные в zz.h:
-	обычная редукция zzRed();
-	редукция Крэндалла zzRedCrand();
-	редукция Барретта zzRedBarr();
-	редукция Монтгомери zzRedMont().

В кольце с редукцией Монтгомери вместо обычного умножения
\code
c <- a * b \mod mod
\endcode
используется специальное умножение
\code
c <- a * b * R^{-1} \mod mod,
\endcode
где R -- минимальное число вида B^n, большее mod.

Мультипликативной единицей в кольце Монтгомери является число R \mod mod,
мультипликативно обратный к a элемент: a^{-1} * R^2 \mod mod.

Число a из обычного кольца вычетов преобразуется в элемент a * R \mod mod 
кольца Монтгомери. После вычислений в кольце выходной элемент b преобразуется 
в число b * R^{-1} \mod mod. 

Кольцо, которое создается с помощью функции zmMontCreate(), является "чистым" 
кольцом Монтгомери. Элементы этого кольца представляются числами "как есть".
Чистые кольца Монтгомери используются в алгоритмах СТБ 1176.2.
В чистом кольце R = 2^l, причем l не обязательно кратно B_PER_W, 
т.е. R не обязательно имеет вид B^n.

\remark Функции zzCreateMont() и zzMontCreate() создают разные кольца.

\pre Все указатели действительны.

\safe todo
*******************************************************************************
*/

/*
*******************************************************************************
Создание описания кольца вычетов целых чисел
*******************************************************************************
*/

/*!	\brief Создание описания кольца вычетов целых чисел с обычной редукцией

	По модулю [no]mod, представленному строкой октетов, создается описание r 
	кольца Z / (mod). При вычислениях в кольце используется обычная редукция.
	\pre no > 0 && mod[no - 1] > 0.
	\post r->no == no и r->n == W_OF_O(no).
	\keep{r} zmCreatePlain_keep(no).
	\deep{stack} zmCreatePlain_deep(no).
*/
void zmCreatePlain(
	qr_o* r,			/*!< [out] описание кольца */
	const octet mod[],	/*!< [in] модуль */
	size_t no,			/*!< [in] длина mod в октетах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zmCreatePlain_keep(size_t no);
size_t zmCreatePlain_deep(size_t no);

/*!	\brief Создание описания кольца вычетов целых чисел с редукцией Крэндалла

	По модулю [no]mod, представленному строкой октетов, создается описание r 
	кольца Z / (mod). При вычислениях в кольце используется редукция Крэндалла.
	\pre no > 0 && mod[no - 1] > 0.
	\pre mod == B^n - c, где n >= 2 && 0 < c < B.
	\post r->no == no и r->n == W_OF_O(no).
	\keep{r} zmCreateCrand_keep(no).
	\deep{stack} zmCreateCrand_deep(no).
*/
void zmCreateCrand(
	qr_o* r,			/*!< [out] описание кольца */
	const octet mod[],	/*!< [in] модуль */
	size_t no,			/*!< [in] длина mod в октетах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zmCreateCrand_keep(size_t no);
size_t zmCreateCrand_deep(size_t no);

/*!	\brief Создание описания кольца вычетов целых чисел с редукцией Барретта

	По модулю [no]mod, представленному строкой октетов, создается описание r 
	кольца Z / (mod). При вычислениях в кольце используется редукция Барретта.
	\pre no > 0 && mod[no - 1] > 0.
	\post r->no == no и r->n == W_OF_O(no).
	\keep{r} zmCreateBarr_keep(no).
	\deep{stack} zmCreateBarr_deep(no).
*/
void zmCreateBarr(
	qr_o* r,			/*!< [out] описание кольца */
	const octet mod[],	/*!< [in] модуль */
	size_t no,			/*!< [in] длина mod в октетах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zmCreateBarr_keep(size_t no);
size_t zmCreateBarr_deep(size_t no);

/*!	\brief Создание описания кольца вычетов целых чисел с редукцией Монтгомери

	По модулю [no]mod, представленному строкой октетов, создается описание r 
	кольца Z / (mod). При вычислениях в кольце используется редукция 
	Монтгомери.
	\pre no > 0 && mod[no - 1] > 0.
	\pre mod -- нечетное число.
	\post r->no == no и r->n == W_OF_O(no).
	\keep{r} zmCreateMont_keep(no).
	\deep{stack} zmCreateMont_deep(no).
*/
void zmCreateMont(
	qr_o* r,			/*!< [out] описание кольца */
	const octet mod[],	/*!< [in] модуль */
	size_t no,			/*!< [in] длина mod в октетах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zmCreateMont_keep(size_t no);
size_t zmCreateMont_deep(size_t no);

/*!	\brief Создание описания кольца вычетов целых чисел

	По модулю [no]mod, представленному строкой октетов, создается описание r 
	кольца Z / (mod). Подбирается оптимальное (с точки зрения эффективности 
	вычислений) описание.
	\pre no > 0 && mod[no - 1] > 0.
	\post r->no == no и r->n == W_OF_O(no).
	\remark Оптимальное кольцо подбирается с учетом следующих 
	результатов экспериментов (2013.09.17):
	-	редукция Крэндалла примерно в 2 раза быстрее редукции Монтгомери;
	-	редукция Монтгомери примерно в 2 раза быстрее редукции Барретта;
	-	редукция Барретта несколько опережает обычную редукцию при r->n >= 4.
	\keep{r} zmCreate_keep(no).
	\deep{stack} zmCreate_deep(no).
*/
void zmCreate(
	qr_o* r,			/*!< [out] описание кольца */
	const octet mod[],	/*!< [in] модуль */
	size_t no,			/*!< [in] длина mod в октетах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zmCreate_keep(size_t no);
size_t zmCreate_deep(size_t no);

/*
*******************************************************************************
Создание описания кольца Монтгомери
*******************************************************************************
*/

/*!	\brief Создание описания кольца Монтгомери

	По модулю [no]mod, представленному строкой октетов, создается описание r 
	кольца Монтгомери c параметром R = 2^l.
	\pre no > 0 && mod[no - 1] > 0.
	\pre mod -- нечетное число.
	\pre mod < R && B^n <= R (n -- число слов для размещения mod).
	\remark Если кольцо построено, то r->no == no и r->n == W_OF_O(no).
	\keep{r} zmMontCreate_keep(no).
	\deep{stack} zmMontCreate_deep(no).
*/
void zmMontCreate(
	qr_o* r,			/*!< [out] описание кольца */
	const octet mod[],	/*!< [in] модуль */
	size_t no,			/*!< [in] длина mod в октетах */
	size_t l,			/*!< [in] показатель в параметре R */ 
	void* stack			/*!< [in] вспомогательная память */
);

size_t zmMontCreate_keep(size_t no);
size_t zmMontCreate_deep(size_t no);

/*
*******************************************************************************
Проверка описания кольца вычетов целых чисел
*******************************************************************************
*/

/*!	\brief Описание кольца вычетов целых чисел корректно?

	Проверяется корректность описания r кольца Z / (mod). Проверяются 
	следующие условия:
	-	qrIsOperable(r) == TRUE;
	-	указатель r->mod корректен;
	-	r->mod[r->n - 1] > 0.
	\return Признак корректности.
	\remark Работоспособность и корректность эквивалентны.
*/
bool_t zmIsValid(
	const qr_o* r		/*!< [in] описание кольца */
);

#define zmIsOperable zmIsValid

/*
*******************************************************************************
Акселераторы

Для ускорения работы вместо обращения к функциям интерфейсов qr_add_i, 
qr_sub_i, qr_neg_i идут прямые обращения к zzAddMod(), zzSubMod(), zzNegMod().
*******************************************************************************
*/

#define zmIsIn(a, r)\
	(wwCmp(a, (r)->mod, (r)->n) < 0)

#define zmAdd(c, a, b, r)\
	zzAddMod(c, a, b, (r)->mod, (r)->n)

#define zmSub(c, a, b, r)\
	zzSubMod(c, a, b, (r)->mod, (r)->n)

#define zmNeg(b, a, r)\
	zzNegMod(b, a, (r)->mod, (r)->n)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __ZM_H */
