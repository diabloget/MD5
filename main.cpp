#include <iostream>
#include <string.h>
#include "md5.h"

int main(int argc, char** argv) {
    const char* BYTES = "Hola";

    md5::md5_t md5;
    md5.process(BYTES, strlen(BYTES));
    md5.finish();

    char str[MD5_STRING_SIZE];

    md5.get_string(str);

    for (unsigned int i = 0; i < MD5_STRING_SIZE; i++)
        std::cout << str[i];

    //Al cambiar la constante Bytes por cualquier otro texto, en la consola se reflejará su versión Hash.
}
