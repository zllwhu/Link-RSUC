# 1. Introduction to Link-RSUC
This is a linkable and randomizable signature of updatable commitments scheme, which is suitable for constructing auditable and privacy-preserving payment channel hubs.

# 2. How to build on Linux
x86-64/ARM/ARM64 Linux are supported. 

## 2.1 Preparations

Before you begin, please make sure you have the following tools on your computer. You can easily install them with `sudo apt install xxx`:
1. `build-essential` for gcc.
2. `autoconf` for creating Makefiles.
3. `libtool` for building dynamic libraries.
4. `libgmp-dev` for big integer calculation.
5. `cmake` for making the project.


Besides, there are some libraries need to be installed:

1. **MCL** is necessary for paring-based cryptography:
    ```
    git clone https://github.com/herumi/mcl
    cd mcl
    mkdir build
    cd build
    cmake ..
    make
    sudo make install
    ```
    Tips: Please use v2.14 version of mcl (`178f8bbe2f1e9ffcdec6e24aa11ae0b1d232b159`).
2. **LibTomCrypt** is necessary for some hash functions:
    ```
    wget https://github.com/libtom/libtomcrypt/archive/refs/tags/v1.18.2.tar.gz
    tar -zxvf libtomcrypt-1.18.2.tar.gz
    cd libtomcrypt-1.18.2
    make
    sudo make install
    ```
3. **secp256k1** is necessary for key generation, build with autotools:
    ```
    wget https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v0.6.0.tar.gz
    tar -zxvf secp256k1-0.6.0.tar.gz
    cd secp256k1-0.6.0
    ./autogen.sh
    ./configure
    make
    sudo make install
    ```

## 2.1 Build with CMake
You need to execute the following commands to compile the project:
```
cd Link-RSUC
mkdir build
cd build
cmake ..
make
```

# 3. How to run on Linux
You need to execute the following commands to run the project:
```
cd ../bin
./EXP1
./EXP2
```

# 4. Cite this project
Please cite this project with:
```
TBD
```
