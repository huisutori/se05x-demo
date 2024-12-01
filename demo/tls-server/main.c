#include <stdio.h>
#include <stdlib.h>
#include "model/secure_element.h"

int main(void)
{
    int err = SecureElement_init();
    if (err) {
        printf("SecureElement_init() failed with error %d\n", err);
        exit(1);
    }

    return 0;
}
