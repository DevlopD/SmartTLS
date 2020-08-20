#ifndef __AES_METHOD_1_H__
#define __AES_METHOD_1_H__

#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/des.h>

#define KEY_BIT 256
typedef unsigned char U8;

int aes_encrypt( U8 *p_in, U8 *p_out, const U8 *cipher_key, U8 *iv_aes, int size)
{
    AES_KEY aes_key;

    AES_set_encrypt_key(cipher_key, KEY_BIT, &aes_key);
    AES_cbc_encrypt(p_in, p_out, size, &aes_key, iv_aes, AES_ENCRYPT);

    return 0;
}

int aes_decrypt( U8 *p_in, U8 *p_out, const U8* cipher_key, U8 *iv_aes, int size)
{
    AES_KEY aes_key;

    AES_set_decrypt_key(cipher_key, KEY_BIT, &aes_key);
    AES_cbc_encrypt(p_in, p_out, size, &aes_key, iv_aes, AES_DECRYPT);

    return 0;
}

#endif /* __AES_METHOD_1_H__ */
