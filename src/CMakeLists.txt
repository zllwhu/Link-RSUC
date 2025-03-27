add_executable(EXP1 exp1.c util.c)
add_executable(EXP2 exp2.c util.c)
target_link_libraries(EXP1 /usr/local/lib/libtomcrypt.a /usr/local/lib/libmclbn256.so /usr/local/lib/libmcl.so /usr/local/lib/libsecp256k1.so)
target_link_libraries(EXP2 /usr/local/lib/libtomcrypt.a /usr/local/lib/libmclbn256.so /usr/local/lib/libmcl.so /usr/local/lib/libsecp256k1.so)
