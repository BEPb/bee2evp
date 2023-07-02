/*
*******************************************************************************
\file prng.h
\brief Pseudorandom number generators
\project bee2 [cryptographic library]
\created 2014.05.02
\version 2023.02.02
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

/*!
*******************************************************************************
\file prng.h
\brief Генераторы псевдослучайных чисел
*******************************************************************************
*/

#ifndef __BEE2_PRNG_H
#define __BEE2_PRNG_H

#include "bee2/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file prng.h

\section prng-combo Генератор COMBO

Генератор COMBO разработан Дж. Марсалья (George Marsaglia,
см. http://www.stat.fsu.edu/pub/diehard/cdrom/pscript/keynote.ps).
Генератор проходит все тесты батареи DIEHARD, период последовательности
его состояний имеет порядок 2^60.

Работа с генератором COMBO состоит в однократном вызове функции
prngCOMBOStart() и последующих многократных вызовах prngCOMBOStepR().
Состояние автомата состоит из prngCOMBO_keep() октетов и
интерпретируется как общий стек указанных функций. Состояние не должно
изменяться между обращениями к функциям.
*******************************************************************************
*/

/*!	\brief Длина состояния функций COMBO

	Возвращается длина состояния функций, реализующих генератор COMBO.
	\return Глубина стека.
*/
size_t prngCOMBO_keep();

/*!	\brief Инициализация генератора COMBO

	Состояние state генератора COMBO инициализируется на основании числа seed.
	\pre По адресу state зарезервировано prngCOMBO_keep() октетов
	памяти.
*/
void prngCOMBOStart(
	void* state,			/*!< [out] состояние COMBO */
	u32 seed				/*!< [in] инициализирующее значение */
);

/*!	\brief Генератор COMBO

	В буфер [count]buf записываются псевдослучайные октеты, построенные 
	с помощью генератора COMBO с состоянием state. Состояние state изменяется
	при генерации.
	\expect prngCOMBOStart() < prngCOMBOStepR()*.
	\remark Поддержан интерфейс gen_i (defs.h).
*/
void prngCOMBOStepR(
	void* buf,				/*!< [out] буфер */
	size_t count,			/*!< [in] размер буфера (в октетах) */
	void* state				/*!< [in,out] состояние COMBO */
);

/*!
*******************************************************************************
\file prng.h

\section prng-echo Эхо-генератор

Эхо-генератор повторяет буфер данных, переданный при инициализации. 
Эхо-генератор удобно использовать при тестировании для передачи фиксированных 
данных через интерфейс prng_i.
*******************************************************************************
*/

/*!	\brief Длина состояния эхо-генератора

	Возвращается длина состояния функций, реализующих эхо-генератор.
	\return Длина состояния.
*/
size_t prngEcho_keep();

/*!	\brief Инициализация эхо-генератора

	Состояние state эхо-генератора инициализируется на основании буфера 
	[seed_len]seed.
	\pre По адресу state зарезервировано prngEcho_keep() октетов.
	\pre seed_len > 0.
	\pre Буфер seed корректен.
	\expect Буфер seed остается корректным на протяжении всей работы
	с состоянием state.
*/
void prngEchoStart(
	void* state,			/*!< [out] состояние эхо-генератора */
	const void* seed,		/*!< [in] инициализирующий буфер */
	size_t seed_len			/*!< [in] длина seed в октетах */
);

/*!	\brief Эхо-генерация

	В буфер [count]buf записываются октеты, построенные с помощью 
	эхо-генератора с состоянием state. Состояние state изменяется
	при генерации.
	\expect prngEchoStart() < prngEchoStepR()*.
	\remark Поддержан интерфейс gen_i (defs.h).
*/
void prngEchoStepR(
	void* buf,				/*!< [out] буфер */
	size_t count,			/*!< [in] размер буфера (в октетах) */
	void* state				/*!< [in,out] состояние */
);

/*!
*******************************************************************************
\file prng.h

\section prng-stb Генератор СТБ

Генератор определен в СТБ 1176.2-99 (п. 7.2.2). Выходные последовательности 
генератора используются при построении простых чисел.
*******************************************************************************
*/

/*!	\brief Длина состояния генератора СТБ

	Возвращается длина состояния функций, реализующих генератор СТБ.
	\return Длина состояния.
*/
size_t prngSTB_keep();

/*!	\brief Инициализация генератора СТБ

	Состояние state генератора СТБ инициализируется по числам массива [31]z.
	При нулевом z предполагается, что z[0] = 1, z[1] = 2,..., z[30] = 31.
	\pre По адресу state зарезервировано prngSTB_keep() октетов.
	\pre Если z != 0, то буфер z корректен.
	\pre Если z != 0, то z[i] > 0 && z[i] < 65257, i = 0, 1,..., 30.
*/
void prngSTBStart(
	void* state,		/*!< [out] состояние генератора */
	const u16 z[31]		/*!< [in] числа z[i] */
);

/*!	\brief Использование генератора СТБ

	В буфер [count]buf записываются октеты, построенные с помощью 
	генератора СТБ с состоянием state. Состояние state изменяется
	при генерации.
	\expect prngSTBStart() < prngSTBStepR()*.
	\remark Поддержан интерфейс gen_i (defs.h).
*/
void prngSTBStepR(
	void* buf,				/*!< [out] буфер */
	size_t count,			/*!< [in] размер буфера (в октетах) */
	void* state				/*!< [in,out] состояние */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_PRNG_H */
