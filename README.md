solhsm-core software
=====================

Simple Light and Open HSM is a project that allows OpenSSL's users to enhance
security by storing private keys on a Harware Security Module based on a
BeagleBoneBlack (or whatever you want). The Hardware Security Module
works with the solHSM-PROTOCOL in order to communicate with an
OpenSSL ENGINE (solHSM-ENGINE) over IP.

solHSM-Core is the main software on the HSM that provides some basic
cyptographic operations.

Please read the [wiki](https://github.com/jjungo/solhsm-core/wiki) for more informations

Requirements
-----------
    >=gcc-4.7
    git://github.com/jedisct1/libsodium.git
    git://github.com/zeromq/libzmq.git
    git://github.com/zeromq/czmq.git
    g++
    libpgm-dev
    cmake
    automake
    libtool
    pkg-config
    libsqlite3-dev
    sqlite3
    libssl-dev
    rsyslog

Install
----------
	chmod +x install_dep.sh dep.sh
    ./install_dep.sh
    ./autogen.sh
    ./configure && make
    sudo make install

Setup and run
----------

In order to communicate with your HSM client (web server), you need to create
and share certificates:

    $ cd tools
    $ make
    $ ./generate_cert cert_name

`./generate_cert cert_name` will create public (`*.cert`) and private
(`*.cert_secret`) certificates.
Keys are generated on 256 bits (ECC with Curve25519).

On the HSM side, certificates **MUST** be in:

    /etc/hsm/server/
    ├── pub_key
    │	│
    │	└── client.cert
    ├── server.cert
    └── server.cert_secret

On the client side, [solhsm-engine](https://github.com/jjungo/solhsm-engine)
you can either build your Docker images with the Dockerfile or place certificates
in appropriate directories (read the solhsm-engine doc).

Run hsm-core:

    /etc/init.d/hsm-core start

Uninstall
---------
Uninstall but keep certificates and database:

    sudo make uninstall

Full uninstall

    sudo make fulluninstall
