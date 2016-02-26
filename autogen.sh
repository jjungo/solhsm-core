#!/usr/bin/env sh

#   Script to generate all required files from fresh git checkout.


command -v libtool >/dev/null 2>&1
if  [ $? -ne 0 ]; then
    echo "autogen.sh: error: could not find libtool.  libtool is required to run autogen.sh." 1>&2
    exit 1
fi

command -v autoreconf >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "autogen.sh: error: could not find autoreconf.  autoconf and automake are required to run autogen.sh." 1>&2
    exit 1
fi

command -v pkg-config >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "autogen.sh: error: could not find pkg-config.  pkg-config is required to run autogen.sh." 1>&2
    exit 1
fi

mkdir config bin

cp README.md README

autoreconf --install --force --verbose -I config
status=$?
if [ $status -ne 0 ]; then
    echo "autogen.sh: error: autoreconf exited with status $status" 1>&2
    exit 1
fi
