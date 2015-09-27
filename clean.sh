#!/bin/bash

# Clean project before pushing it on git repo

rm -r autom4te.cache config bin
rm aclocal.m4 config.log  missing compile config.status Makefile config.h configure config.h.in install-sh  Makefile.in  stamp-h1 
rm *~
rm src/Makefile

