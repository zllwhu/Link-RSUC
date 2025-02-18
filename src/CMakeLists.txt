add_executable(LinkRSUC main.c util.c)
target_link_libraries(LinkRSUC /usr/local/lib/libtomcrypt.a /usr/local/lib/libmclbn256.so /usr/local/lib/libmcl.so /usr/local/lib/libsecp256k1.so)
