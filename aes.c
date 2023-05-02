#include <stdio.h>
#include <memory.h>
#include "aes.h"
//#include "./utils.h"

//
// Public Definitions
//

/* moved to rijndael.h */

//
// Internal Definitions
//

/*
 * Encryption Rounds
 */
int g_aes_key_bits[] = {
    /* AES_CYPHER_128 */ 128,
    /* AES_CYPHER_192 */ 192,
    /* AES_CYPHER_256 */ 256,
};

int g_aes_rounds[] = {
    /* AES_CYPHER_128 */  10,
    /* AES_CYPHER_192 */  12,
    /* AES_CYPHER_256 */  14,
};

int g_aes_nk[] = {
    /* AES_CYPHER_128 */  4,
    /* AES_CYPHER_192 */  6,
    /* AES_CYPHER_256 */  8,
};

int g_aes_nb[] = {
    /* AES_CYPHER_128 */  4,
    /* AES_CYPHER_192 */  4,
    /* AES_CYPHER_256 */  4,
};

//********CFB*******//
int g_cfb_rbits[] = {
    // define how many bits we use in each loop
    // to do XOR operation with IV.
    /* CFB_CYPHER_1 */ 1,
    /* CFB_CYPHER_8 */ 8,
    ///* CFB_CYPHER_128 */ 1,
};
//******************//


/*
 * aes Rcon:
 *
 * WARNING: Rcon is designed starting from 1 to 15, not 0 to 14.
 *          FIPS-197 Page 9: "note that i starts at 1, not 0"
 *
 * i    |   0     1     2     3     4     5     6     7     8     9    10    11    12    13    14
 * -----+------------------------------------------------------------------------------------------
 *      | [01]  [02]  [04]  [08]  [10]  [20]  [40]  [80]  [1b]  [36]  [6c]  [d8]  [ab]  [4d]  [9a]
 * RCON | [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]
 *      | [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]
 *      | [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]
 */
 
static const uint32_t g_aes_rcon[] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000, 0x6c000000, 0xd8000000, 0xab000000, 0xed000000, 0x9a000000
};

/* aes sbox and invert-sbox */
static const uint8_t g_aes_sbox[256] = {
 /* 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F  */
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t g_inv_sbox[256] = {
 /* 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F  */
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

//The result of all hexadecimal numbers multiplied by 2 in GF(2^8)
static const uint8_t TE2[256] = {
    0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
    0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
    0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
    0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
    0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
    0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
    0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
    0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
    0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
    0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
    0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
    0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
    0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
    0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
    0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
    0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
};
//The result of all hexadecimal numbers multiplied by 3 in GF(2^8)
static const uint8_t TE3[256] = {
    0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
    0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
    0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
    0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
    0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
    0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
    0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
    0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
    0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
    0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
    0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
    0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
    0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
    0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
    0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
    0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a
};
//The result of all hexadecimal numbers multiplied by b in GF(2^8)
static const uint8_t TDb[256] = {
    0x00,0x0b,0x16,0x1d,0x2c,0x27,0x3a,0x31,0x58,0x53,0x4e,0x45,0x74,0x7f,0x62,0x69,
    0xb0,0xbb,0xa6,0xad,0x9c,0x97,0x8a,0x81,0xe8,0xe3,0xfe,0xf5,0xc4,0xcf,0xd2,0xd9,
    0x7b,0x70,0x6d,0x66,0x57,0x5c,0x41,0x4a,0x23,0x28,0x35,0x3e,0x0f,0x04,0x19,0x12,
    0xcb,0xc0,0xdd,0xd6,0xe7,0xec,0xf1,0xfa,0x93,0x98,0x85,0x8e,0xbf,0xb4,0xa9,0xa2,
    0xf6,0xfd,0xe0,0xeb,0xda,0xd1,0xcc,0xc7,0xae,0xa5,0xb8,0xb3,0x82,0x89,0x94,0x9f,
    0x46,0x4d,0x50,0x5b,0x6a,0x61,0x7c,0x77,0x1e,0x15,0x08,0x03,0x32,0x39,0x24,0x2f,
    0x8d,0x86,0x9b,0x90,0xa1,0xaa,0xb7,0xbc,0xd5,0xde,0xc3,0xc8,0xf9,0xf2,0xef,0xe4,
    0x3d,0x36,0x2b,0x20,0x11,0x1a,0x07,0x0c,0x65,0x6e,0x73,0x78,0x49,0x42,0x5f,0x54,
    0xf7,0xfc,0xe1,0xea,0xdb,0xd0,0xcd,0xc6,0xaf,0xa4,0xb9,0xb2,0x83,0x88,0x95,0x9e,
    0x47,0x4c,0x51,0x5a,0x6b,0x60,0x7d,0x76,0x1f,0x14,0x09,0x02,0x33,0x38,0x25,0x2e,
    0x8c,0x87,0x9a,0x91,0xa0,0xab,0xb6,0xbd,0xd4,0xdf,0xc2,0xc9,0xf8,0xf3,0xee,0xe5,
    0x3c,0x37,0x2a,0x21,0x10,0x1b,0x06,0x0d,0x64,0x6f,0x72,0x79,0x48,0x43,0x5e,0x55,
    0x01,0x0a,0x17,0x1c,0x2d,0x26,0x3b,0x30,0x59,0x52,0x4f,0x44,0x75,0x7e,0x63,0x68,
    0xb1,0xba,0xa7,0xac,0x9d,0x96,0x8b,0x80,0xe9,0xe2,0xff,0xf4,0xc5,0xce,0xd3,0xd8,
    0x7a,0x71,0x6c,0x67,0x56,0x5d,0x40,0x4b,0x22,0x29,0x34,0x3f,0x0e,0x05,0x18,0x13,
    0xca,0xc1,0xdc,0xd7,0xe6,0xed,0xf0,0xfb,0x92,0x99,0x84,0x8f,0xbe,0xb5,0xa8,0xa3
};
//The result of all hexadecimal numbers multiplied by 9 in GF(2^8)
static const uint8_t TD9[256] = {
    0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x41, 0x5a, 0x53, 0x6c, 0x65, 0x7e, 0x77, 0x90, 0x99, 0x82,
    0x8b, 0xb4, 0xbd, 0xa6, 0xaf, 0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7, 0x3b, 0x32, 0x29, 0x20, 0x1f, 0x16,
    0x0d, 0x04, 0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c, 0xab, 0xa2, 0xb9, 0xb0, 0x8f, 0x86, 0x9d, 0x94, 0xe3,
    0xea, 0xf1, 0xf8, 0xc7, 0xce, 0xd5, 0xdc, 0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49, 0x3e, 0x37, 0x2c, 0x25,
    0x1a, 0x13, 0x08, 0x01, 0xe6, 0xef, 0xf4, 0xfd, 0xc2, 0xcb, 0xd0, 0xd9, 0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98,
    0x91, 0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72, 0x05, 0x0c, 0x17, 0x1e, 0x21, 0x28, 0x33, 0x3a, 0xdd, 0xd4,
    0xcf, 0xc6, 0xf9, 0xf0, 0xeb, 0xe2, 0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa, 0xec, 0xe5, 0xfe, 0xf7, 0xc8,
    0xc1, 0xda, 0xd3, 0xa4, 0xad, 0xb6, 0xbf, 0x80, 0x89, 0x92, 0x9b, 0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a, 0x43,
    0x34, 0x3d, 0x26, 0x2f, 0x10, 0x19, 0x02, 0x0b, 0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8, 0x9f, 0x96, 0x8d,
    0x84, 0xbb, 0xb2, 0xa9, 0xa0, 0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6a, 0x71, 0x78, 0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22,
    0x39, 0x30, 0x9a, 0x93, 0x88, 0x81, 0xbe, 0xb7, 0xac, 0xa5, 0xd2, 0xdb, 0xc0, 0xc9, 0xf6, 0xff, 0xe4, 0xed, 0x0a,
    0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35, 0x42, 0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d, 0xa1, 0xa8, 0xb3, 0xba,
    0x85, 0x8c, 0x97, 0x9e, 0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf, 0xd6, 0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07,
    0x0e, 0x79, 0x70, 0x6b, 0x62, 0x5d, 0x54, 0x4f, 0x46
};

//The result of all hexadecimal numbers multiplied by d in GF(2^8)
static const uint8_t TDd[256] = {
    0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23, 0x68, 0x65, 0x72, 0x7f, 0x5c, 0x51, 0x46, 0x4b, 0xd0, 0xdd, 0xca, 
    0xc7, 0xe4, 0xe9, 0xfe, 0xf3, 0xb8, 0xb5, 0xa2, 0xaf, 0x8c, 0x81, 0x96, 0x9b, 0xbb, 0xb6, 0xa1, 0xac, 0x8f, 0x82, 
    0x95, 0x98, 0xd3, 0xde, 0xc9, 0xc4, 0xe7, 0xea, 0xfd, 0xf0, 0x6b, 0x66, 0x71, 0x7c, 0x5f, 0x52, 0x45, 0x48, 0x03, 
    0x0e, 0x19, 0x14, 0x37, 0x3a, 0x2d, 0x20, 0x6d, 0x60, 0x77, 0x7a, 0x59, 0x54, 0x43, 0x4e, 0x05, 0x08, 0x1f, 0x12, 
    0x31, 0x3c, 0x2b, 0x26, 0xbd, 0xb0, 0xa7, 0xaa, 0x89, 0x84, 0x93, 0x9e, 0xd5, 0xd8, 0xcf, 0xc2, 0xe1, 0xec, 0xfb, 
    0xf6, 0xd6, 0xdb, 0xcc, 0xc1, 0xe2, 0xef, 0xf8, 0xf5, 0xbe, 0xb3, 0xa4, 0xa9, 0x8a, 0x87, 0x90, 0x9d, 0x06, 0x0b, 
    0x1c, 0x11, 0x32, 0x3f, 0x28, 0x25, 0x6e, 0x63, 0x74, 0x79, 0x5a, 0x57, 0x40, 0x4d, 0xda, 0xd7, 0xc0, 0xcd, 0xee, 
    0xe3, 0xf4, 0xf9, 0xb2, 0xbf, 0xa8, 0xa5, 0x86, 0x8b, 0x9c, 0x91, 0x0a, 0x07, 0x10, 0x1d, 0x3e, 0x33, 0x24, 0x29, 
    0x62, 0x6f, 0x78, 0x75, 0x56, 0x5b, 0x4c, 0x41, 0x61, 0x6c, 0x7b, 0x76, 0x55, 0x58, 0x4f, 0x42, 0x09, 0x04, 0x13, 
    0x1e, 0x3d, 0x30, 0x27, 0x2a, 0xb1, 0xbc, 0xab, 0xa6, 0x85, 0x88, 0x9f, 0x92, 0xd9, 0xd4, 0xc3, 0xce, 0xed, 0xe0, 
    0xf7, 0xfa, 0xb7, 0xba, 0xad, 0xa0, 0x83, 0x8e, 0x99, 0x94, 0xdf, 0xd2, 0xc5, 0xc8, 0xeb, 0xe6, 0xf1, 0xfc, 0x67, 
    0x6a, 0x7d, 0x70, 0x53, 0x5e, 0x49, 0x44, 0x0f, 0x02, 0x15, 0x18, 0x3b, 0x36, 0x21, 0x2c, 0x0c, 0x01, 0x16, 0x1b, 
    0x38, 0x35, 0x22, 0x2f, 0x64, 0x69, 0x7e, 0x73, 0x50, 0x5d, 0x4a, 0x47, 0xdc, 0xd1, 0xc6, 0xcb, 0xe8, 0xe5, 0xf2, 
    0xff, 0xb4, 0xb9, 0xae, 0xa3, 0x80, 0x8d, 0x9a, 0x97
};
//The result of all hexadecimal numbers multiplied by e in GF(2^8)
static const uint8_t TDe[256] = {
    0x00,0x0e,0x1c,0x12,0x38,0x36,0x24,0x2a,0x70,0x7e,0x6c,0x62,0x48,0x46,0x54,0x5a,
    0xe0,0xee,0xfc,0xf2,0xd8,0xd6,0xc4,0xca,0x90,0x9e,0x8c,0x82,0xa8,0xa6,0xb4,0xba,
    0xdb,0xd5,0xc7,0xc9,0xe3,0xed,0xff,0xf1,0xab,0xa5,0xb7,0xb9,0x93,0x9d,0x8f,0x81,
    0x3b,0x35,0x27,0x29,0x03,0x0d,0x1f,0x11,0x4b,0x45,0x57,0x59,0x73,0x7d,0x6f,0x61,
    0xad,0xa3,0xb1,0xbf,0x95,0x9b,0x89,0x87,0xdd,0xd3,0xc1,0xcf,0xe5,0xeb,0xf9,0xf7,
    0x4d,0x43,0x51,0x5f,0x75,0x7b,0x69,0x67,0x3d,0x33,0x21,0x2f,0x05,0x0b,0x19,0x17,
    0x76,0x78,0x6a,0x64,0x4e,0x40,0x52,0x5c,0x06,0x08,0x1a,0x14,0x3e,0x30,0x22,0x2c,
    0x96,0x98,0x8a,0x84,0xae,0xa0,0xb2,0xbc,0xe6,0xe8,0xfa,0xf4,0xde,0xd0,0xc2,0xcc,
    0x41,0x4f,0x5d,0x53,0x79,0x77,0x65,0x6b,0x31,0x3f,0x2d,0x23,0x09,0x07,0x15,0x1b,
    0xa1,0xaf,0xbd,0xb3,0x99,0x97,0x85,0x8b,0xd1,0xdf,0xcd,0xc3,0xe9,0xe7,0xf5,0xfb,
    0x9a,0x94,0x86,0x88,0xa2,0xac,0xbe,0xb0,0xea,0xe4,0xf6,0xf8,0xd2,0xdc,0xce,0xc0,
    0x7a,0x74,0x66,0x68,0x42,0x4c,0x5e,0x50,0x0a,0x04,0x16,0x18,0x32,0x3c,0x2e,0x20,
    0xec,0xe2,0xf0,0xfe,0xd4,0xda,0xc8,0xc6,0x9c,0x92,0x80,0x8e,0xa4,0xaa,0xb8,0xb6,
    0x0c,0x02,0x10,0x1e,0x34,0x3a,0x28,0x26,0x7c,0x72,0x60,0x6e,0x44,0x4a,0x58,0x56,
    0x37,0x39,0x2b,0x25,0x0f,0x01,0x13,0x1d,0x47,0x49,0x5b,0x55,0x7f,0x71,0x63,0x6d,
    0xd7,0xd9,0xcb,0xc5,0xef,0xe1,0xf3,0xfd,0xa7,0xa9,0xbb,0xb5,0x9f,0x91,0x83,0x8d
};


// uint8_t aes_sub_sbox(uint8_t val){
//     return g_aes_sbox[val];
// }

uint32_t aes_sub_dword(uint32_t val){
    // use S-box's value to each of the 4 bytes in the argument.
    uint32_t tmp = 0;
   
    // bitwise OR operation.
    tmp |= ((uint32_t)g_aes_sbox[(uint8_t)((val >>  0) & 0xFF)]) <<  0;
    tmp |= ((uint32_t)g_aes_sbox[(uint8_t)((val >>  8) & 0xFF)]) <<  8;
    tmp |= ((uint32_t)g_aes_sbox[(uint8_t)((val >> 16) & 0xFF)]) << 16;
    tmp |= ((uint32_t)g_aes_sbox[(uint8_t)((val >> 24) & 0xFF)]) << 24;

    return tmp;
}

uint32_t aes_rot_dword(uint32_t val){
    // shift elements.
    uint32_t tmp = val;
   
    return (val >> 8) | ((tmp & 0xFF) << 24);
}

uint32_t aes_swap_dword(uint32_t val){
    return (((val & 0x000000FF) << 24) |
            ((val & 0x0000FF00) <<  8) |
            ((val & 0x00FF0000) >>  8) |
            ((val & 0xFF000000) >> 24) );
}

/*
 * nr: number of rounds
 * nb: number of columns comprising the state, nb = 4 dwords (16 bytes)
 * nk: number of 32-bit words comprising cipher key, nk = 4, 6, 8 (KeyLength/(4*8))
 */

void aes_key_expansion(AES_CYPHER_T mode, uint8_t *key, uint8_t *round){
    uint32_t *w = (uint32_t *)round;
    uint32_t  t;
    int i = 0;

    // printf("Key Expansion:\n"); // For debug only
    do {
        // for first four ws, just assign key value to it.
        w[i] = *((uint32_t *) & key[i * 4 + 0]);
        // printf("    %2.2d:  rs: %8.8x\n", i, aes_swap_dword(w[i])); // For debug only
    } while (++i < g_aes_nk[mode]);
   
    do {
        // calculate last 12 ws.
        // printf("    %2.2d: ", i); // For debug only
        if ((i % g_aes_nk[mode]) == 0) {
            t = aes_rot_dword(w[i - 1]);
            // printf(" rot: %8.8x", aes_swap_dword(t)); // For debug only
            t = aes_sub_dword(t);
            // printf(" sub: %8.8x", aes_swap_dword(t)); // For debug only
            // printf(" rcon: %8.8x", g_aes_rcon[i/g_aes_nk[mode] - 1]); // For debug only
            t = t ^ aes_swap_dword(g_aes_rcon[i / g_aes_nk[mode] - 1]);
            // printf(" xor: %8.8x", t); // For debug only
        } else if (g_aes_nk[mode] > 6 && (i % g_aes_nk[mode]) == 4) {
            t = aes_sub_dword(w[i - 1]);
            // printf(" sub: %8.8x", aes_swap_dword(t)); // For debug only
        } else {
            t = w[i - 1];
            // printf(" equ: %8.8x", aes_swap_dword(t)); // For debug only
        }
        w[i] = w[i - g_aes_nk[mode]] ^ t;
        // printf(" rs: %8.8x\n", aes_swap_dword(w[i])); // For debug only
    } while (++i < g_aes_nb[mode] * (g_aes_rounds[mode] + 1));
   
    /* key can be discarded (or zeroed) from memory */
}

void aes_add_round_key(AES_CYPHER_T mode, uint8_t *state,
                       uint8_t *round, int nr){
    // declare pointers for round and state.
    uint32_t *w = (uint32_t *)round;
    uint32_t *s = (uint32_t *)state;
   
    // ???
    for (int i = 0; i < g_aes_nb[mode]; i++) {
        s[i] ^= w[nr * g_aes_nb[mode] + i];
    }
}

//Combine subbytes and shiftrows.Do both at the same time
void aes_sub_shift(AES_CYPHER_T mode, uint8_t* state)
{
    //The order in which state is stored is [s0,s4,s8,s12,    s1, s5, s9, s13,    s2, s6, s10, s14,    s3, s7, s11, s15]
    // after shift_rows the order is        [s0,s4,s8,s12,     s5, s9, s13,s1,     s10, s14,s2, s6,     s15,s3, s7, s11,]
    // just substitute row 0
    uint8_t tmp;
    // just substitute row 0
    state[0] = g_aes_sbox[state[0]], state[4] = g_aes_sbox[state[4]];
    state[8] = g_aes_sbox[state[8]], state[12] = g_aes_sbox[state[12]];

    // rotate row 1
    tmp = g_aes_sbox[state[1]], state[1] = g_aes_sbox[state[5]];
    state[5] = g_aes_sbox[state[9]], state[9] = g_aes_sbox[state[13]], state[13] = tmp;

    // rotate row 2
    tmp = g_aes_sbox[state[2]], state[2] = g_aes_sbox[state[10]], state[10] = tmp;
    tmp = g_aes_sbox[state[6]], state[6] = g_aes_sbox[state[14]], state[14] = tmp;

    // rotate row 3
    tmp = g_aes_sbox[state[15]], state[15] = g_aes_sbox[state[11]];
    state[11] = g_aes_sbox[state[7]], state[7] = g_aes_sbox[state[3]], state[3] = tmp;
}


void aes_sub_shift_mix (AES_CYPHER_T mode, uint8_t* state)
{
uint8_t tmp[16];

// column 1

tmp[0] = TE2[g_aes_sbox[state[0]]] ^ TE3[g_aes_sbox[state[5]]] ^ g_aes_sbox[state[10]] ^ g_aes_sbox[state[15]];

tmp[1] = g_aes_sbox[state[0]] ^ TE2[g_aes_sbox[state[5]]] ^ TE3[g_aes_sbox[state[10]]] ^ g_aes_sbox[state[15]];

tmp[2] = g_aes_sbox[state[0]] ^ g_aes_sbox[state[5]] ^ TE2[g_aes_sbox[state[10]]] ^ TE3[g_aes_sbox[state[15]]];

tmp[3] = TE3[g_aes_sbox[state[0]]] ^ g_aes_sbox[state[5]] ^ g_aes_sbox[state[10]] ^ TE2[g_aes_sbox[state[15]]];

// column 2

tmp[4] = TE2[g_aes_sbox[state[4]]] ^ TE3[g_aes_sbox[state[9]]] ^ g_aes_sbox[state[14]] ^ g_aes_sbox[state[3]];

tmp[5] = g_aes_sbox[state[4]] ^ TE2[g_aes_sbox[state[9]]] ^ TE3[g_aes_sbox[state[14]]] ^ g_aes_sbox[state[3]];

tmp[6] = g_aes_sbox[state[4]] ^ g_aes_sbox[state[9]] ^ TE2[g_aes_sbox[state[14]]] ^ TE3[g_aes_sbox[state[3]]];

tmp[7] = TE3[g_aes_sbox[state[4]]] ^ g_aes_sbox[state[9]] ^ g_aes_sbox[state[14]] ^ TE2[g_aes_sbox[state[3]]];

// column 3

tmp[8] = TE2[g_aes_sbox[state[8]]] ^ TE3[g_aes_sbox[state[13]]] ^ g_aes_sbox[state[2]] ^ g_aes_sbox[state[7]];

tmp[9] = g_aes_sbox[state[8]] ^ TE2[g_aes_sbox[state[13]]] ^ TE3[g_aes_sbox[state[2]]] ^ g_aes_sbox[state[7]];

tmp[10] = g_aes_sbox[state[8]] ^ g_aes_sbox[state[13]] ^ TE2[g_aes_sbox[state[2]]] ^ TE3[g_aes_sbox[state[7]]];

tmp[11] = TE3[g_aes_sbox[state[8]]] ^ g_aes_sbox[state[13]] ^ g_aes_sbox[state[2]] ^ TE2[g_aes_sbox[state[7]]];

// column 4

tmp[12] = TE2[g_aes_sbox[state[12]]] ^ TE3[g_aes_sbox[state[1]]] ^ g_aes_sbox[state[6]] ^ g_aes_sbox[state[11]];

tmp[13] = g_aes_sbox[state[12]] ^ TE2[g_aes_sbox[state[1]]] ^ TE3[g_aes_sbox[state[6]]] ^ g_aes_sbox[state[11]];

tmp[14] = g_aes_sbox[state[12]] ^ g_aes_sbox[state[1]] ^ TE2[g_aes_sbox[state[6]]] ^ TE3[g_aes_sbox[state[11]]];

tmp[15] = TE3[g_aes_sbox[state[12]]] ^ g_aes_sbox[state[1]] ^ g_aes_sbox[state[6]] ^ TE2[g_aes_sbox[state[11]]];

memcpy(state, tmp, sizeof(tmp));

}

void aes_sub_bytes(AES_CYPHER_T mode, uint8_t *state){
    // traverse the whole state, get each value in S-box.
    for (int i = 0; i < g_aes_nb[mode]; i++) {
        for (int j = 0; j < 4; j++) {
            // pass index of current plaintext,
            // find its value in S-box according to its index.
            state[i * 4 + j] = g_aes_sbox[state[i * 4 + j]];
        }
    }
}

void aes_shift_rows(AES_CYPHER_T mode, uint8_t *state){
    // declare pointer point to state.
    uint8_t *s = (uint8_t *) state;

    // for each row, do shift operation.
    for (int i = 1; i < g_aes_nb[mode]; i++) {
        for (int j = 0; j < i; j++) {
            uint8_t tmp = s[i];
            // here use for loop to change elements' value.
            for (int r = 0; r < g_aes_nb[mode]; r++) {
                s[i + r * 4] = s[i + (r + 1) * 4];
            }
            s[i + (g_aes_nb[mode] - 1) * 4] = tmp;
        }
    }
}

uint8_t aes_xtime(uint8_t x){
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

uint8_t aes_xtimes(uint8_t x, int ts){
    // hexidecimal multiplation.
    // divde it into multiple number operation.
    while (ts-- > 0) {
        x = aes_xtime(x);
    }
    return x;
}

uint8_t aes_mul(uint8_t x, uint8_t y){
    /*
     * encrypt: y has only 2 bits: can be 1, 2 or 3
     * decrypt: y could be any value of 9, b, d, or e
     */
   
    return ((((y >> 0) & 1) * aes_xtimes(x, 0)) ^
            (((y >> 1) & 1) * aes_xtimes(x, 1)) ^
            (((y >> 2) & 1) * aes_xtimes(x, 2)) ^
            (((y >> 3) & 1) * aes_xtimes(x, 3)) ^
            (((y >> 4) & 1) * aes_xtimes(x, 4)) ^
            (((y >> 5) & 1) * aes_xtimes(x, 5)) ^
            (((y >> 6) & 1) * aes_xtimes(x, 6)) ^
            (((y >> 7) & 1) * aes_xtimes(x, 7)) );
}

uint8_t checkTable(uint8_t s, uint8_t y) {
    if (y == 1)
        return s;
    if (y == 2)
        return TE2[(int)s];
    if (y == 3)
        return TE3[(int)s];
    if (y == 0x09)
        return TD9[(int)s];
    if (y == 0x0b)
        return TDb[(int)s];
    if (y == 0x0d)
        return TDd[(int)s];
    if (y == 0x0e)
        return TDe[(int)s];
}

void aes_mix_columns(AES_CYPHER_T mode, uint8_t *state)
{
    uint8_t y[16] = { 2, 3, 1, 1,  1, 2, 3, 1,  1, 1, 2, 3,  3, 1, 1, 2};
    uint8_t s[4];
    int i, j, r;
    for (i = 0; i < g_aes_nb[mode]; i++) {
        for (r = 0; r < 4; r++) {
            //s[4]
            s[r] = 0;
            for (j = 0; j < 4; j++) {

                s[r] = s[r] ^ checkTable(state[i * 4 + j], y[r * 4 + j]);
            }
        }
        for (r = 0; r < 4; r++) {
            state[i * 4 + r] = s[r];
        }
    }
}

void inv_mix_columns(AES_CYPHER_T mode, uint8_t *state)
{
    uint8_t y[16] = { 0x0e, 0x0b, 0x0d, 0x09,  0x09, 0x0e, 0x0b, 0x0d,
                      0x0d, 0x09, 0x0e, 0x0b,  0x0b, 0x0d, 0x09, 0x0e};
    uint8_t s[4];
    int i, j, r;
   
    for (i = 0; i < g_aes_nb[mode]; i++) {
        for (r = 0; r < 4; r++) {
            s[r] = 0;
            for (j = 0; j < 4; j++) {
                s[r] = s[r] ^ checkTable(state[i * 4 + j], y[r * 4 + j]);
            }
        }
        for (r = 0; r < 4; r++) {
            state[i * 4 + r] = s[r];
        }
    }
}


void aes_dump(char *msg, uint8_t *data, int len){
    
    printf("%8.8s: ", msg);
    for (int i = 0; i < len; i++) {
        printf(" %2.2x", data[i]);
    }
    printf("\n");
    return;
}

int aes_encrypt(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key){
    // initialize w and s.
    uint8_t w[4 * 4 * 15] = {0}; /* round key */
    uint8_t s[4 * 4] = {0}; /* state */
   
    //firstly, generate key.
    /* key expansion */
    aes_key_expansion(mode, key, w);
   
    /* start data cypher loop over input buffer */
    for (int i = 0; i < len; i += 4 * g_aes_nb[mode]){
        // printf("Encrypting block at %u ...\n", i); // For debug only

        /* init state from user buffer (plaintext) */
        for (int j = 0; j < 4 * g_aes_nb[mode]; j++)
            s[j] = data[i + j];
       
        /* start AES cypher loop over all AES rounds */
        for (int nr = 0; nr <= g_aes_rounds[mode]; nr++) {

            // printf(" Round %d:\n", nr); // For debug only
            // aes_dump("input", s, 4 * g_aes_nb[mode]); // For debug only

            if (nr > 0 && nr < g_aes_rounds[mode]) {
                aes_sub_shift_mix(mode, s);
            }
            else if(nr == g_aes_rounds[mode]) {
                aes_sub_shift(mode, s);
            }
           
            /* do AddRoundKey */
            aes_add_round_key(mode, s, w, nr);
            // aes_dump("  round", &w[nr * 4 * g_aes_nb[mode]], 4 * g_aes_nb[mode]); // For debug only
            // aes_dump("  state", s, 4 * g_aes_nb[mode]); // For debug only
        }

        /* save state (cypher) to user buffer */
        for (int j = 0; j < 4 * g_aes_nb[mode]; j++)
            data[i + j] = s[j];
        // printf("Output:\n"); // For debug only
        //aes_dump("cypher", &data[i], 4 * g_aes_nb[mode]); // For debug only
    }
    
    return 0;
}

int aes_encrypt_ecb(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key){
    // simply do encrypt operation.
    return aes_encrypt(mode, data, len, key);
}

int aes_encrypt_cbc(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv){
    // key and state initialize.
    uint8_t w[4 * 4 * 15] = {0}; /* round key */
    uint8_t s[4 * 4] = {0}; /* state */
    // initialize vector.
    uint8_t v[4 * 4] = {0}; /* iv */

    // key generate operation.
    /* key expansion */
    aes_key_expansion(mode, key, w);

    // declare a memory of initialize vector.
    memcpy(v, iv, sizeof(v));
   
    /* start data cypher loop over input buffer */
    for (int i = 0; i < len; i += 4 * g_aes_nb[mode]){

        /* init state from user buffer (plaintext) */
        for (int j = 0; j < 4 * g_aes_nb[mode]; j++){
            s[j] = data[i + j] ^ v[j];
        }
       
        /* start AES cypher loop over all AES rounds */
        for (int nr = 0; nr <= g_aes_rounds[mode]; nr++){

            // aes_dump("input", s, 4 * g_aes_nb[mode]); // For debug only
            if (nr > 0) {
               
                /* do SubBytes */
                aes_sub_bytes(mode, s);
                // aes_dump("  sub", s, 4 * g_aes_nb[mode]); // For debug only

                /* do ShiftRows */
                aes_shift_rows(mode, s);
                // aes_dump("  shift", s, 4 * g_aes_nb[mode]); // For debug only

                if (nr < g_aes_rounds[mode]) {
                    /* do MixColumns */
                    aes_mix_columns(mode, s);
                    // aes_dump("  mix", s, 4 * g_aes_nb[mode]); // For debug only
                }
            }
           
            /* do AddRoundKey */
            aes_add_round_key(mode, s, w, nr);
            // aes_dump("  round", &w[nr * 4 * g_aes_nb[mode]], 4 * g_aes_nb[mode]); // For debug only
            // aes_dump("  state", s, 4 * g_aes_nb[mode]); // For debug only
        }
       
        /* save state (cipher) to user buffer */
        for (int j = 0; j < 4 * g_aes_nb[mode]; j++)
            data[i + j] = v[j] = s[j];
    }
   
    return 0;
}

// here is decrypt operation definition.
void inv_shift_rows(AES_CYPHER_T mode, uint8_t *state){
    uint8_t *s = (uint8_t *)state;
   
    for (int i = 1; i < g_aes_nb[mode]; i++) {
        for (int j = 0; j < g_aes_nb[mode] - i; j++) {
            uint8_t tmp = s[i];
            for (int r = 0; r < g_aes_nb[mode]; r++) {
                s[i + r * 4] = s[i + (r + 1) * 4];
            }
            s[i + (g_aes_nb[mode] - 1) * 4] = tmp;
        }
    }
}

//Combine inv_sub_bytes and inv_shift_rows
void inv_shift_sub(AES_CYPHER_T mode, uint8_t* state)
{

    uint8_t tmp;
    // restore row 0
    state[0] = g_inv_sbox[state[0]], state[4] = g_inv_sbox[state[4]];
    state[8] = g_inv_sbox[state[8]], state[12] = g_inv_sbox[state[12]];

    // restore row 1
    tmp = g_inv_sbox[state[13]], state[13] = g_inv_sbox[state[9]];
    state[9] = g_inv_sbox[state[5]], state[5] = g_inv_sbox[state[1]], state[1] = tmp;

    // restore row 2
    tmp = g_inv_sbox[state[2]], state[2] = g_inv_sbox[state[10]], state[10] = tmp;
    tmp = g_inv_sbox[state[6]], state[6] = g_inv_sbox[state[14]], state[14] = tmp;

    // restore row 3
    tmp = g_inv_sbox[state[3]], state[3] = g_inv_sbox[state[7]];
    state[7] = g_inv_sbox[state[11]], state[11] = g_inv_sbox[state[15]], state[15] = tmp;
}


void inv_mix_shift_sub(AES_CYPHER_T mode, uint8_t* state)
{
    uint8_t tmp[16];

    tmp[0] = TDe[state[0]] ^ TDb[state[1]] ^ TDd[state[2]] ^ TD9[state[3]];
    tmp[5] = TD9[state[0]] ^ TDe[state[1]] ^ TDb[state[2]] ^ TDd[state[3]];
    tmp[10] = TDd[state[0]] ^ TD9[state[1]] ^ TDe[state[2]] ^ TDb[state[3]];
    tmp[15] = TDb[state[0]] ^ TDd[state[1]] ^ TD9[state[2]] ^ TDe[state[3]];

    tmp[4] = TDe[state[4]] ^ TDb[state[5]] ^ TDd[state[6]] ^ TD9[state[7]];
    tmp[9] = TD9[state[4]] ^ TDe[state[5]] ^ TDb[state[6]] ^ TDd[state[7]];
    tmp[14] = TDd[state[4]] ^ TD9[state[5]] ^ TDe[state[6]] ^ TDb[state[7]];
    tmp[3] = TDb[state[4]] ^ TDd[state[5]] ^ TD9[state[6]] ^ TDe[state[7]];

    // restore column 2
    tmp[8] = TDe[state[8]] ^ TDb[state[9]] ^ TDd[state[10]] ^ TD9[state[11]];
    tmp[13] = TD9[state[8]] ^ TDe[state[9]] ^ TDb[state[10]] ^ TDd[state[11]];
    tmp[2] = TDd[state[8]] ^ TD9[state[9]] ^ TDe[state[10]] ^ TDb[state[11]];
    tmp[7] = TDb[state[8]] ^ TDd[state[9]] ^ TD9[state[10]] ^ TDe[state[11]];

    // restore column 3
    tmp[12] = TDe[state[12]] ^ TDb[state[13]] ^ TDd[state[14]] ^ TD9[state[15]];
    tmp[1] = TD9[state[12]] ^ TDe[state[13]] ^ TDb[state[14]] ^ TDd[state[15]];
    tmp[6] = TDd[state[12]] ^ TD9[state[13]] ^ TDe[state[14]] ^ TDb[state[15]];
    tmp[11] = TDb[state[12]] ^ TDd[state[13]] ^ TD9[state[14]] ^ TDe[state[15]];

    for (int i = 0; i < 4 * g_aes_nb[mode]; i++)
        state[i] = g_inv_sbox[tmp[i]];
}

void inv_sub_bytes(AES_CYPHER_T mode, uint8_t *state){
    for (int i = 0; i < g_aes_nb[mode]; i++) {
        for (int j = 0; j < 4; j++) {
            // sub_box????
            state[i * 4 + j] = g_inv_sbox[state[i * 4 + j]];
        }
    }
}


int aes_decrypt(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key){
    uint8_t w[4 * 4 * 15] = {0}; /* round key */
    uint8_t s[4 * 4] = {0}; /* state */
   
    int nr, i, j;
   
    /* key expansion */
    aes_key_expansion(mode, key, w);
   
    /* start data cypher loop over input buffer */
    for (i = 0; i < len; i += 4 * g_aes_nb[mode]) {
       
        // printf("Decrypting block at %u ...\n", i);
       
        /* init state from user buffer (cyphertext) */
        for (j = 0; j < 4 * g_aes_nb[mode]; j++)
            s[j] = data[i + j];
       
        /* start AES cypher loop over all AES rounds */
        for (nr = g_aes_rounds[mode]; nr >= 0; nr--) {

            // printf(" Round %d:\n", nr); // For debug only
            // aes_dump("input", s, 4 * g_aes_nb[mode]); // For debug only

            /* do AddRoundKey */
            aes_add_round_key(mode, s, w, nr);
            // aes_dump("  round", &w[nr * 4 * g_aes_nb[mode]], 4 * g_aes_nb[mode]); // For debug only

            if (nr > 0) {

                if (nr == g_aes_rounds[mode]) {
                        inv_shift_sub(mode, s);
                }
                else if (nr < g_aes_rounds[mode]) {
                        inv_mix_shift_sub(mode, s);
                }

            }
            // aes_dump("  state", s, 4 * g_aes_nb[mode]); // For debug only
        }
       
        /* save state (cypher) to user buffer */
        for (j = 0; j < 4 * g_aes_nb[mode]; j++)
            data[i + j] = s[j];
        // printf("Output:\n"); // For debug only
        // aes_dump("plain", &data[i], 4 * g_aes_nb[mode]); // For debug only
    }
   
    return 0;
}

int aes_decrypt_ecb(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key){
    return aes_decrypt(mode, data, len, key);
}

int aes_decrypt_cbc(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv){
    uint8_t w[4 * 4 * 15] = {0}; /* round key */
    uint8_t s[4 * 4] = {0}; /* state */
    uint8_t v[4 * 4] = {0}; /* iv */

   
    int nr, i, j;
   
    /* key expansion */
    aes_key_expansion(mode, key, w);
   
    memcpy(v, iv, sizeof(v));

    /* start data cypher loop over input buffer */
    for (i = 0; i < len; i += 4 * g_aes_nb[mode]) {
       
        /* init state from user buffer (cyphertext) */
        for (j = 0; j < 4 * g_aes_nb[mode]; j++)
            s[j] = data[i + j];
       
        /* start AES cypher loop over all AES rounds */
        for (nr = g_aes_rounds[mode]; nr >= 0; nr--) {
           
            // aes_dump("input", s, 4 * g_aes_nb[mode]);

            /* do AddRoundKey */
            aes_add_round_key(mode, s, w, nr);
            // aes_dump("  round", &w[nr * 4 * g_aes_nb[mode]], 4 * g_aes_nb[mode]);


            if (nr > 0) {

                if (nr < g_aes_rounds[mode]) {
                    // aes_dump("  mix", s, 4 * g_aes_nb[mode]);
                    /* do MixColumns */
                    inv_mix_columns(mode, s);
                }

                /* do ShiftRows */
                // aes_dump("  shift", s, 4 * g_aes_nb[mode]);
                inv_shift_rows(mode, s);

                /* do SubBytes */
                // aes_dump("  sub", s, 4 * g_aes_nb[mode]);
                inv_sub_bytes(mode, s);
            }
           
            // aes_dump("  state", s, 4 * g_aes_nb[mode]);
        }
       
        /* save state (cypher) to user buffer */
        for (j = 0; j < 4 * g_aes_nb[mode]; j++) {
            uint8_t p = s[j] ^ v[j];
            v[j] = data[i + j];
            data[i + j] = p;
        }
    }
   
    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//CTR by Edward Cai
int aes_xcrypt_ctr(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv){ //对于CTR，加密解密用同一个函数
    // key and state initialize.
    uint8_t w[4 * 4 * 15] = {0}; /* round key */
    uint8_t s[4 * 4] = {0}; /* state */
    // initialize vector.
    uint8_t v[4 * 4] = {0}; /* iv */

    // key generate operation.
    /* key expansion */
    aes_key_expansion(mode, key, w);

   
    /* start data cypher loop over input buffer */
    for (int i = 0; i < len; i += 4 * g_aes_nb[mode]){
        // declare a memory of initialize vector.
        memcpy(v, iv, sizeof(v)); //because every round we need to update counter(IV)
        if(i!=0){
            v[15] += i/16;   //rebuild the counter
            //aes_dump("v-----------", v, 16);
            //aes_dump("iv-----------", iv, 16);
        }

        /* init state from user buffer (plaintext) */
        for (int j = 0; j < 4 * g_aes_nb[mode]; j++){
            s[j] = data[i + j]; //transform the ciphertext/plaintext in to state(4x4)
            //s[j] = data[i + j] ^ v[j];
        }
       
        /* start AES cypher loop over all AES rounds */
        for (int nr = 0; nr <= g_aes_rounds[mode]; nr++){

            // aes_dump("input", s, 4 * g_aes_nb[mode]); // For debug only
            if (nr > 0) {
               
                /* do SubBytes */
                aes_sub_bytes(mode, v);
                // aes_dump("  sub", s, 4 * g_aes_nb[mode]); // For debug only

                /* do ShiftRows */
                aes_shift_rows(mode, v);
                // aes_dump("  shift", s, 4 * g_aes_nb[mode]); // For debug only

                if (nr < g_aes_rounds[mode]) {
                    /* do MixColumns */
                    aes_mix_columns(mode, v);
                    // aes_dump("  mix", s, 4 * g_aes_nb[mode]); // For debug only
                }
            }
           
            /* do AddRoundKey */
            aes_add_round_key(mode, v, w, nr);
            // aes_dump("  round", &w[nr * 4 * g_aes_nb[mode]], 4 * g_aes_nb[mode]); // For debug only
            // aes_dump("  state", s, 4 * g_aes_nb[mode]); // For debug only
        }
       
        /* save state (cipher) to user buffer */
        for (int j = 0; j < 4 * g_aes_nb[mode]; j++)
            data[i + j] = s[j] ^ v[j];
    }

    return 0;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//CTR by Edward Cai



/*
    CFB Model
    by Wendy WANG
    */

int aes_xcrypt_cfb(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv) {
    uint8_t w[4 * 4 * 15] = {0}; /* round key */
    uint8_t s[4 * 4] = {0}; /* state */
    uint8_t v[4 * 4] = {0}; /* iv */

    /* key expansion */
    // key -- input; w -- round key output.
    aes_key_expansion(mode, key, w);
   
    // for each loop, allocate memory for initial vector.
    memcpy(v, iv, sizeof(v));

    // for each 16 bytes, we enter here and do en/decryption.
    /* start data cypher loop over input buffer */
    // for (int i = 0; i < len; i += 4 * g_aes_nb[mode]) {
    for (int i = 0; i < len; i += 1) {

        // assign iv's value to s, as initialization.
        for (int k = 0; k < 16; k++) {
            s[k] = iv[k];
        }
        // aes_dump("after assign iv", s, 4 * g_aes_nb[mode]); // For debug only

        /* start AES cypher loop over all AES rounds */
        for (int nr = 0; nr <= g_aes_rounds[mode]; nr++) {

            // aes_dump("input", s, 4 * g_aes_nb[mode]); // For debug only
            /* do SubBytes */
            aes_sub_bytes(mode, s);
            // aes_dump("  sub", s, 4 * g_aes_nb[mode]); // For debug only

            /* do ShiftRows */
            aes_shift_rows(mode, s);
            // aes_dump("  shift", s, 4 * g_aes_nb[mode]); // For debug only

            if (nr < g_aes_rounds[mode]) {
                /* do MixColumns */
                aes_mix_columns(mode, s);
                // aes_dump("  mix", s, 4 * g_aes_nb[mode]); // For debug only
            }

            /* do AddRoundKey */
            aes_add_round_key(mode, s, w, nr);
            // aes_dump("  round", &w[nr * 4 * g_aes_nb[mode]], 4 * g_aes_nb[mode]); // For debug only
            // aes_dump("  state", s, 4 * g_aes_nb[mode]); // For debug only
        }

        // after encryption,
        // take r bits to do encryption with r bits plaintext.
        // length of r according to type of CFB.
        // let r-bits plaintext and above result do XOR operation.
        uint8_t temp = s[0];
        s[0] = s[15] ^ data[i];

        // let next state shift left r bits, add above r bits to its right.
        /* save state (cipher) to user buffer */
        for (int j = 14; j > 1; j--){
            // let iv shift 8-bit left.
            s[j] = s[j - 1];
        }
        s[1] = temp;

        data[i] = s[0];
    }

    return 0;
}

//******************//

/*
    OFB Model
    by Wendy WANG
    */

int aes_xcrypt_ofb(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv) {
    uint8_t w[4 * 4 * 15] = {0}; /* round key */
    uint8_t s[4 * 4] = {0}; /* state */
    uint8_t v[4 * 4] = {0}; /* iv */

    /* key expansion */
    // key -- input; w -- round key output.
    aes_key_expansion(mode, key, w);
   
    // for each loop, allocate memory for initial vector.
    memcpy(v, iv, sizeof(v));

    // for each 16 bytes, we enter here and do en/decryption.
    /* start data cypher loop over input buffer */
    // for (int i = 0; i < len; i += 4 * g_aes_nb[mode]) {
    for (int i = 0; i < len; i += 1) {

        // assign iv's value to s, as initialization.
        for (int k = 0; k < 16; k++) {
            s[k] = iv[k];
        }
        // aes_dump("after assign iv", s, 4 * g_aes_nb[mode]); // For debug only

        /* start AES cypher loop over all AES rounds */
        for (int nr = 0; nr <= g_aes_rounds[mode]; nr++) {

            // aes_dump("input", s, 4 * g_aes_nb[mode]); // For debug only
            /* do SubBytes */
            aes_sub_bytes(mode, s);
            // aes_dump("  sub", s, 4 * g_aes_nb[mode]); // For debug only

            /* do ShiftRows */
            aes_shift_rows(mode, s);
            // aes_dump("  shift", s, 4 * g_aes_nb[mode]); // For debug only

            if (nr < g_aes_rounds[mode]) {
                /* do MixColumns */
                aes_mix_columns(mode, s);
                // aes_dump("  mix", s, 4 * g_aes_nb[mode]); // For debug only
            }

            /* do AddRoundKey */
            aes_add_round_key(mode, s, w, nr);
            // aes_dump("  round", &w[nr * 4 * g_aes_nb[mode]], 4 * g_aes_nb[mode]); // For debug only
            // aes_dump("  state", s, 4 * g_aes_nb[mode]); // For debug only
        }

        // after encryption,
        // take r bits to do encryption with r bits plaintext.
        // length of r according to type of CFB.
        // let r-bits plaintext and above result do XOR operation.
        uint8_t temp = s[0];
        s[0] = s[15];

        // let next state shift left r bits, add above r bits to its right.
        /* save state (cipher) to user buffer */
        for (int j = 14; j > 1; j--) {
            // let iv shift 8-bit left.
            s[j] = s[j - 1];
        }
        s[1] = temp;

        data[i] = temp ^ data[i];
    }

    return 0;
}

//******************//