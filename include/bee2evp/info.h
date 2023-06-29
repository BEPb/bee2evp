/*
*******************************************************************************
\file info.h
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Common info
\created 2012.04.01
\version 2021.07.14
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

/*!
*******************************************************************************
\file info.h
\brief Общая информация
*******************************************************************************
*/


#ifndef __BEE2EVP_INFO
#define __BEE2EVP_INFO

#define BEE2EVP_NAME			"Bee2evp"
#define BEE2EVP_VERSION_MAJOR	"1"
#define BEE2EVP_VERSION_MINOR 	"0"
#define BEE2EVP_VERSION_PATCH	"8"

#define BEE2EVP_VERSION\
		BEE2EVP_VERSION_MAJOR "." BEE2EVP_VERSION_MINOR "." BEE2EVP_VERSION_PATCH

#define BEE2EVP_VERSION_NUM\
		1, 0, 8

/*!
*******************************************************************************
\mainpage Криптографический плагин Bee2evp для OpenSSL

\version 1.0.8

\section toc Содержание

-#	\ref descr
-#	\ref make
-#	\ref license

\section descr Описание

Библиотека bee2evp является плагином (engine) популярной криптографической 
библиотеки OpenSSL. Плагин предоставляет криптографические сервисы библиотеки 
bee2 по интерфейсу EVP.

\section make Сборка

Подготовка конфигурационных файлов:

\verbatim
mkdir build
cd build
cmake  ..
\endverbatim

Конфигурация отладочной версии:

\verbatim
cmake -DCMAKE_BUILD_TYPE=Debug ..
\endverbatim

Конфигурация со средствами мониторинга покрытия:

\verbatim
cmake -DCMAKE_BUILD_TYPE=Coverage ..
\endverbatim

Конфигурация со средствами проверки адресов (AddressSanitizer):

\verbatim
cmake -DCMAKE_BUILD_TYPE=ASan ..
cmake -DCMAKE_BUILD_TYPE=ASanDbg ..
\endverbatim

Конфигурация со средствами проверки памяти (MemorySanitizer):

\verbatim
cmake -DCMAKE_BUILD_TYPE=MemSan ..
cmake -DCMAKE_BUILD_TYPE=MemSanDbg ..
\endverbatim

Конфигурация со строгой компиляцией:

\verbatim
cmake -DCMAKE_BUILD_TYPE=Check ..
\endverbatim

Сборка:

\verbatim
make
\endverbatim

Установка:

\verbatim
make install
\endverbatim

\section license Лицензия

Библиотека распространяется на условиях Apache License, Version 2.0. 

*******************************************************************************
*/

#endif // __BEE2EVP_INFO
