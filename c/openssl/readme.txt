

1. Build and install openssl library.
2. Dynamic lnik: gcc ./sha_1.c -L./   -I./include -lssl -lcrypto  -o ttt
3. Static link: gcc ./sha_1.c ./libssl.a ./libcrypto.a    -I./include -ldl -lpthread  -o ttt -static




