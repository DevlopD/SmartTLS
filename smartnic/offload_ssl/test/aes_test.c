#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <aes_method_1.h>
#include <aes_method_2.h>

static const U8 cipher_key[]= {0x9f, 0xda, 0xb8, 0x27, 0xd1, 0x71, 0xd4, 0xe7, \
                               0xc9, 0x7f, 0x11, 0xd5, 0x23, 0x04, 0xf8, 0x77, \
                               0x05, 0x2e, 0xcd, 0xa1, 0xa4, 0x8a, 0x3e, 0x5f, \
                               0x72, 0x52, 0x92, 0xcc, 0x16, 0xd5, 0xa5, 0x9a};

static U8 iv_aes[] = {0xba, 0x56, 0x3e, 0xa2, 0x57, 0xf9, 0x6b, 0x45, \
                      0x21, 0x66, 0x8e, 0x6e, 0xa6, 0xef, 0x8c, 0xbb};
#define KEY_BIT 256


int main(int argc, char *args[])
{
    U8      p_sour[] = {0x59, 0x63, 0x6c, 0x5f, 0x64, 0x3e, 0xe9, 0x07, \
                        0xa8, 0x6e, 0x64, 0x9f, 0xe3, 0x77, 0xbf, 0x0b, \
                        0x14, 0x00, 0x00, 0x0c, 0x7d, 0x6d, 0x12, 0xca, \
                        0xd6, 0x00, 0x60, 0x52, 0xe3, 0xc6, 0xb4, 0xea, \
                        0xbc, 0x7e, 0xfa, 0xe5, 0x23, 0x17, 0x5e, 0x3d, \
                        0xd0, 0xbe, 0x83, 0x43, 0xa6, 0xff, 0x0c, 0x21, \
                        0x0e, 0x47, 0x07, 0x14, 0xa1, 0x74, 0x2c, 0x32, \
                        0xab, 0xf4, 0x6f, 0xa1, 0x5d, 0xb3, 0x0e, 0x78};
    U8      p_encrypt[1024];
    U8      p_decrypt[1024];
    U8      p_temp[1024];
    int     encrypt_size, ndx;

    printf( "original data: ");
    for ( ndx = 0; ndx < sizeof( p_sour); ndx++){
        printf( "0x%02x ", p_sour[ndx]);
    }
    printf( "\n\n");

    aes_encrypt(p_sour, p_encrypt, cipher_key, iv_aes, sizeof( p_sour));
    printf( "encrypt aes: ");
    for ( ndx = 0; ndx < sizeof( p_sour); ndx++){
        printf( "0x%02x ", p_encrypt[ndx]);
    }
    printf( "\n\n");

    encrypt_size    = ( sizeof( p_sour) + AES_BLOCK_SIZE) /16 * 16;
    memcpy( p_temp, p_encrypt, encrypt_size);
    aes_decrypt(p_encrypt, p_decrypt, cipher_key, iv_aes, encrypt_size);


    printf( "decrypt aes: ");
    for ( ndx = 0; ndx < sizeof( p_sour); ndx++){
        printf( "0x%02x ", p_decrypt[ndx]);
    }
    printf( "\n");

    return 0;
}


#if 0
int main (void)
{
    /*
 *      * Set up the key and iv. Do I need to say to not hard code these in a
 *           * real application? :-)
 *                */

    /* A 256 bit key */
    unsigned char key[] = {0x9f, 0xda, 0xb8, 0x27, 0xd1, 0x71, 0xd4, 0xe7, \
                           0xc9, 0x7f, 0x11, 0xd5, 0x23, 0x04, 0xf8, 0x77, \
                           0x05, 0x2e, 0xcd, 0xa1, 0xa4, 0x8a, 0x3e, 0x5f, \
                           0x72, 0x52, 0x92, 0xcc, 0x16, 0xd5, 0xa5, 0x9a};

    /* A 128 bit IV */
    unsigned char iv[] = {0xba, 0x56, 0x3e, 0xa2, 0x57, 0xf9, 0x6b, 0x45, \
                          0x21, 0x66, 0x8e, 0x6e, 0xa6, 0xef, 0x8c, 0xbb};

    /* Message to be encrypted */
    unsigned char plaintext[] = {0x59, 0x63, 0x6c, 0x5f, 0x64, 0x3e, 0xe9, 0x07, \
                                 0xa8, 0x6e, 0x64, 0x9f, 0xe3, 0x77, 0xbf, 0x0b, \
                                 0x14, 0x00, 0x00, 0x0c, 0x7d, 0x6d, 0x12, 0xca, \
                                 0xd6, 0x00, 0x60, 0x52, 0xe3, 0xc6, 0xb4, 0xea, \
                                 0xbc, 0x7e, 0xfa, 0xe5, 0x23, 0x17, 0x5e, 0x3d, \
                                 0xd0, 0xbe, 0x83, 0x43, 0xa6, 0xff, 0x0c, 0x21, \
                                 0x0e, 0x47, 0x07, 0x14, 0xa1, 0x74, 0x2c, 0x32, \
                                 0xab, 0xf4, 0x6f, 0xa1, 0x5d, 0xb3, 0x0e, 0x78};

    /*
 *      * Buffer for ciphertext. Ensure the buffer is long enough for the
 *           * ciphertext which may be longer than the plaintext, depending on the
 *                * algorithm and mode.
 *                     */
    unsigned char ciphertext[128];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len, plaintext_len;

    plaintext_len = sizeof(plaintext);
    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext, plaintext_len, key, iv,
                              ciphertext);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, plaintext_len);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
                                decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    BIO_dump_fp (stdout, (const char *)decryptedtext, plaintext_len);

    return 0;
}
#endif
