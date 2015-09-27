solhsm-core software
=====================

Simple Light and Open HSM is project that allows OpenSSL's users to enhance 
security by storing private keys on a Harware Security Module based on a 
BeagleBoneBlack (or whatever if you want). The Hardware Security Module
works with the solHSM-PROTOCOL in order to communicate over IP with an
OpenSSL ENGINE (solHSM-ENGINE).

solHSM-Core is the main software on the HSM that provide some basics 
cyptographic operations.

Requirement 
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
    
How to use
----------
    /etc/init.d/hsm-core start

In order to comuunicate with your hsm client (web server), you need to create 
and share certificates. In order to create certificates, go to the tools DIR and 
follow these instructions.

    $ make
    $ ./generate_cert name

Certificates MUST be in:

    /etc/hsm/server/
    ├── pub_key
    │	│
    │	└── client.cert
    ├── server.cert
    └── server.cert_secret

Uninstall
---------
Uninstall but keep cert and database:

    sudo make uninstall

Full uninstall

    sudo make fulluninstall


