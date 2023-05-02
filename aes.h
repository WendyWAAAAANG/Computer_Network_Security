#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AES_CYPHER_128,
    AES_CYPHER_192,
    AES_CYPHER_256,
} AES_CYPHER_T;

//********CFB*******//
typedef enum {
    CFB_CYPHER_1,
    CFB_CYPHER_8,
    CFB_CYPHER_128,
} CFB_CYPHER_T;
//******************//

#ifdef _MSC_VER
    #if _MSC_VER >= 1600
        #include <stdint.h>
    #else
        typedef __int8              int8_t;
        typedef __int16             int16_t;
        typedef __int32             int32_t;
        typedef __int64             int64_t;
        typedef unsigned __int8     uint8_t;
        typedef unsigned __int16    uint16_t;
        typedef unsigned __int32    uint32_t;
        typedef unsigned __int64    uint64_t;
    #endif
#elif __GNUC__ >= 3
    #include <stdint.h>
#endif
// #define GMULT_TABLE // comment it if GMULT_TABLE is disable

int aes_encrypt(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key);
int aes_decrypt(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key);
int aes_encrypt_ecb(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key);
int aes_decrypt_ecb(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key);
int aes_encrypt_cbc(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv);
int aes_decrypt_cbc(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv);
///////////////////////////////////////////////////////////////////////////////////////////////
int aes_xcrypt_ctr(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv);
///////////////////////////////////////////////////////////////////////////////////////////////
//********CFB*******//
int aes_xcrypt_cfb(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv);
//******************//
//********OFB*******//
int aes_xcrypt_ofb(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv);
//******************//
void aes_dump(char *msg, uint8_t *data, int len);

#ifdef __cplusplus
};
#endif