#!/bin/sh

set +x

SOURCE_DIR=$(pwd)

BUILD_DIR=$SOURCE_DIR"/build"

if [ -d "$BUILD_DIR" ]; then
    cd build || exit
    cmake .. && make
elif [ ! -d "$BUILD_DIR" ]; then
    mkdir build && cd build || exit
    cmake .. && make
fi
