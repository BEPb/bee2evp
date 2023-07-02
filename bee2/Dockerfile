# Определяется базовый образ, используемый для создания контейнера - btls/debian:cdev с указанием платформы TARGETPLATFORM.
FROM --platform=$TARGETPLATFORM btls/debian:cdev

#Копируется текущая директория внутрь контейнера в путь /usr/src.
COPY . /usr/src
#Выполняется установка и проверка версии GCC.
RUN gcc --version
#Выполняется установка и проверка версии Clang.
RUN clang --version
#Выполняется вывод информации о дистрибутиве ОС, на которой запущен контейнер.
RUN cat /etc/os-release

#Устанавливается рабочая директория контейнера /usr/src и создаются директории build_gcc и build_clang.
WORKDIR /usr/src
#Удаляется директория build_gcc и создается заново.
RUN rm -rf ./build_gcc; mkdir build_gcc
#Удаляется директория build_clang и создается заново.
RUN rm -rf ./build_clang; mkdir build_clang


#Устанавливается рабочая директория контейнера /usr/src/build_gcc.
WORKDIR /usr/src/build_gcc
#Устанавливается переменная окружения CC со значением gcc и выполняется сборка проекта через CMake.
RUN CC=gcc cmake ..
#Выполняется команда make, которая запускает компиляцию проекта.
# Команда RUN make в данном Dockerfile выполняет компиляцию проекта, используя файлы с исходным кодом в директории
# /usr/src. Это происходит после выполнения команды CC=gcc clang .. (или CC=clang cmake ..) которая генерирует \
#  Makefile на основе файла CMakeLists.txt, который находится также в /usr/src директории.
RUN make
#Выполняется команда make install, которая устанавливает скомпилированные файлы.
RUN make install
#Выполняется команда ctest --verbose, которая запускает автоматические тесты.
RUN ctest --verbose
#Выполняется команда ../cmd/test/test.sh, которая запускает скрипт с тестами.
RUN ../cmd/test/test.sh

#Устанавливается рабочая директория контейнера /usr/src/build_clang.
WORKDIR /usr/src/build_clang
#Устанавливается переменная окружения CC со значением clang и выполняется сборка проекта через CMake.
RUN CC=clang cmake ..
#Выполняется команда make, которая запускает компиляцию проекта.
RUN make
#Выполняется команда make install, которая устанавливает скомпилированные файлы.
RUN make install
#Выполняется команда ctest --verbose, которая запускает автоматические тесты.
RUN ctest --verbose
#Выполняется команда ../cmd/test/test.sh, которая запускает скрипт с тестами.
RUN ../cmd/test/test.sh
#Устанавливается рабочая директория контейнера /usr/src.
WORKDIR /usr/src