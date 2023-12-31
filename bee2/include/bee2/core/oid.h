/*
*******************************************************************************
\file oid.h
\brief Object identifiers
\project bee2 [cryptographic library]
\created 2013.02.04
\version 2022.07.06
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

/*!
*******************************************************************************
\file oid.h
\brief Идентификаторы объектов
*******************************************************************************
*/


#ifndef __BEE2_OID_H
#define __BEE2_OID_H

#include "bee2/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file oid.h

Идентификатор объекта (object identifier) представляет собой
последовательность неотрицательных целых чисел d1, d2,.., dn.

OID представляется строкой, составленной из последовательных чисел
d1, d2,..., dn, разделенных точками. Числа di записываются
десятичными цифрами, без лидирующих нулей. 	При этом строковое
представление оказывается однозначным.

Корректный идентификатор "d1.d2....dn" удовлетворяет следующим
ограничениям ASN.1:
-	n >= 2;
-	d1 <= 2;
-	если d1 < 2, то d2 < 40.

Дополнительные ограничения реализации:
-	число 40 * d1 + d2  укладывается в u32;
-	числа di укладываются в u32.

Примеры идентификаторов (см. СТБ 34.101.50):
-	"1.2.112" --- корневой идентификатор РБ;
-	"1.2.112.0.2" --- стандарты РБ;
-	"1.2.112.0.2.0" --- СТБ.

\safe Функции модуля нерегулярны: обрабатываемые идентификаторы не считаются 
секретными.

\pre Входные буферы не пересекаются.
*******************************************************************************
*/

/*
*******************************************************************************
Проверка
*******************************************************************************
*/

/*!	\brief Корректный OID?

	Проверяется корректность идентификатора oid.
	\return Признак корректности.
*/
bool_t oidIsValid(
	const char* oid		/*!< [in] идентификатор объекта */
);

/*
*******************************************************************************
Преобразования
*******************************************************************************
*/

/*!	\brief DER-кодирование

	Определяется число октетов в DER-коде идентификатора oid. Если der != 0, 
	то DER-код размещается по этому адресу.
	\pre Если der != 0, то по адресу der зарезервировано oidToDER(0, oid)
	октетов.
	\return Число октетов в DER-коде или SIZE_MAX в случае неверного 
	формата oid.
	\remark Формируется октет тега.
*/
size_t oidToDER(
	octet der[],		/*!< [out] DER-код */
	const char* oid		/*!< [in] идентификатор объекта */
);

/*!	\brief DER-декодирование

	Определяется число символов (исключая завершающий нулевой) для размещения
	идентификатора, представленного DER-кодом [count]der.
	Если oid != 0, то идентификатор размещается по этому адресу.
	\pre Если oid != 0, то по адресу oid зарезервировано
	oidFromDER(0, buf, count) октетов.
	\return Число символов или SIZE_MAX в случае ошибки формата.
*/
size_t oidFromDER(
	char* oid,			/*!< [out] идентификатор объекта */
	const octet buf[],	/*!< [in] DER-код */
	size_t count		/*!< [in] длина DER-код */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_OID_H */
