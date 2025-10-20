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

# 5. Q&A
### Problem Description  
In Ubuntu, I compiled and installed the mcl library using `make` and `make install`. The shared library `libmcl.so.1` exists in `/usr/local/lib/`, but when executing another program, an error occurs:  
`error while loading shared libraries: libmcl.so.1: cannot open shared object file: no such file or directory`  

The CMake configuration for the program is as follows:  
```cmake
add_executable(EXP1 exp1.c util.c)
add_executable(EXP2 exp2.c util.c)
target_link_libraries(EXP1 /usr/local/lib/libtomcrypt.a /usr/local/lib/libmclbn256.so /usr/local/lib/libmcl.so /usr/local/lib/libsecp256k1.so)
target_link_libraries(EXP2 /usr/local/lib/libtomcrypt.a /usr/local/lib/libmclbn256.so /usr/local/lib/libmcl.so /usr/local/lib/libsecp256k1.so)
```  

Note: Both `libmcl.so` and `libmcl.so.1` are symbolic links pointing to `/usr/local/lib/libmcl.so.1.74`.  


### Solution  
The error occurs because the system's dynamic linker (`ld.so`) cannot locate `libmcl.so.1`, even though the library exists in `/usr/local/lib`. This is typically because `/usr/local/lib` is not included in the dynamic linker's search path.  

To resolve this:  

1. **Permanently add `/usr/local/lib` to the dynamic linker's configuration**:  
   Create a configuration file to specify the path and update the linker cache:  
   ```bash
   sudo sh -c 'echo "/usr/local/lib" > /etc/ld.so.conf.d/local.conf'
   sudo ldconfig
   ```  

2. **Verify the fix**:  
   Re-run the program. The dynamic linker will now recognize `libmcl.so.1` in `/usr/local/lib`.  


This solution ensures `/usr/local/lib` is permanently recognized by the system's dynamic linker, resolving the "shared library not found" error.
