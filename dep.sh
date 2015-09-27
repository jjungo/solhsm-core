#!/bin/bash

echo "Installing libsodium..."
git clone git://github.com/jedisct1/libsodium.git
cd libsodium
./autogen.sh
./configure && make check
make install
ldconfig
cd ..

echo "Installing libzmq..."
git clone git://github.com/zeromq/libzmq.git
cd libzmq
./autogen.sh
./configure && make check
make install
ldconfig
cd ..

echo "Installing czmq..."
git clone git://github.com/zeromq/czmq.git
cd czmq
./autogen.sh
./configure && make check
make install
ldconfig
cd ..






