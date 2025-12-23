/*
  AES Version 1.4 pjc.co.jp (modified)

  Original code:
  Copyright (C) 2009  PJC.CO.JP
  Licensed under the GNU GPL v2 or later.

  Modifications:
  - Generate random 128-bit AES key at runtime
  - Read plaintext (up to 16 ASCII chars) from user via scanf
  - Perform AES-128 encryption and decryption
  - Print key, original plaintext, ciphertext, and deciphered text
  - Send key and original plaintext to FPGA
  - Receive AES-128 Ciphertext from FPGA.


*/
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "hwlib.h"
#include "socal/socal.h"
#include "socal/hps.h"
#include "socal/alt_gpio.h"
#include "hps_0.h"
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define NB  4      /* number of 32-bit words in state (block size = 4*4 = 16 bytes) */
#define NBb 16     /* number of bytes in block */
#define HW_REGS_BASE ( ALT_STM_OFST )
#define HW_REGS_SPAN ( 0x04000000 )
#define HW_REGS_MASK ( HW_REGS_SPAN - 1 )
#define BARRIER() __sync_synchronize()

/************************************************************/
unsigned char key[32];    /* we'll only use first 16 bytes for AES-128 */
int w[60];                /* key schedule (FIPS 197 P.19 5.2 Key Expansion) */
int data[NB];
int cipher_from_fpga [NB];
const int nk = 4;         /* key length in 32-bit words: 4,6,8 (128,192,256 bits) */
const int nr = 10;        /* number of rounds: 10,12,14 */

/* Function prototypes */
int aes_encrypt(unsigned char *key, int *data);
int aes_decrypt(unsigned char *key, int *data);

void SubBytes(int *);
void ShiftRows(int *);
void MixColumns(int *);
void AddRoundKey(int *, int);

int SubWord(int);
int RotWord(int);
void KeyExpansion(unsigned char *);

int Cipher(int *);
int InvCipher(int *);

void InvSubBytes(int *);
void InvShiftRows(int *);
void InvMixColumns(int *);

void datadump(char c[], void *dt, int len);

void bytes_to_state(const unsigned char *in, int *data);
void state_to_bytes(const int *data, unsigned char *out);

void init_inv_sbox(void);

/************************************************************/
/* S-box (FIPS 197 P.16 Figure 7) */
int Sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Inverse S-box will be computed at runtime from Sbox[] */
int InvSbox[256];

/************************************************************/
void datadump(char c[], void *dt, int len)
{
  int i;
  unsigned char *cdt = (unsigned char *)dt;
  printf("%s", c);
  for (i = 0; i < len * 4; i++) {
    printf("%02x", cdt[i]);
  }
  printf("\n");
}

/************************************************************/

void init_inv_sbox(void)
{
  int i;
  for (i = 0; i < 256; i++) {
    InvSbox[Sbox[i]] = i;
  }
}

/************************************************************/
/* Map 16 bytes into 4 words (same way original code did with 'init[]') */
void bytes_to_state(const unsigned char *in, int *data)
{
  int i, j;
  int wrk;
  for (i = 0; i < NBb / 4; i++) {
    wrk = 0;
    for (j = 3; j >= 0; j--) {
      wrk = (wrk << 8) | in[i * 4 + j];
    }
    data[i] = wrk;
  }
}

/* Map 4 words (state) back into 16 bytes (reverse of above) */
void state_to_bytes(const int *data, unsigned char *out)
{
  int i, j;
  for (i = 0; i < NBb / 4; i++) {
    for (j = 0; j < 4; j++) {
      out[i * 4 + j] = (unsigned char)((data[i] >> (8 * j)) & 0xff);
    }
  }
}

/************************************************************/
/* FIPS 197  P.15 Figure 5 */
int Cipher(int *data)
{
  int i;

  AddRoundKey(data, 0);

  for (i = 1; i < nr; i++) {
    SubBytes(data);
    ShiftRows(data);
    MixColumns(data);
    AddRoundKey(data, i);
  }

  SubBytes(data);
  ShiftRows(data);
  AddRoundKey(data, i);

  return i;
}

/************************************************************/
/* Inverse Cipher (decryption) */
int InvCipher(int *data)
{
  int i;

  AddRoundKey(data, nr);

  for (i = nr - 1; i >= 1; i--) {
    InvShiftRows(data);
    InvSubBytes(data);
    AddRoundKey(data, i);
    InvMixColumns(data);
  }

  InvShiftRows(data);
  InvSubBytes(data);
  AddRoundKey(data, 0);

  return 0;
}

/************************************************************/
/* FIPS 197  P.16 Figure 6 */
void SubBytes(int *data)
{
  int i, j;
  unsigned char cb[4];
  int wrk;

  for (i = 0; i < NBb; i += 4) {
    wrk = data[i / 4];

    for (j = 0; j < 4; j++) {
      cb[j] = (unsigned char)Sbox[(wrk >> ((3 - j) * 8)) & 0xff];
    }

    wrk = 0;
    for (j = 0; j < 4; j++) {
      wrk = (wrk << 8) | cb[j];
    }

    data[i / 4] = wrk;
  }
}

/************************************************************/
/* Inverse SubBytes */
void InvSubBytes(int *data)
{
  int i, j;
  unsigned char cb[4];
  int wrk;

  for (i = 0; i < NBb; i += 4) {
    wrk = data[i / 4];

    for (j = 0; j < 4; j++) {
      cb[j] = (unsigned char)InvSbox[(wrk >> ((3 - j) * 8)) & 0xff];
    }

    wrk = 0;
    for (j = 0; j < 4; j++) {
      wrk = (wrk << 8) | cb[j];
    }

    data[i / 4] = wrk;
  }
}

/************************************************************/
/* FIPS 197  P.17 Figure 8 */
void ShiftRows(int *data)
{
  int i, j;
  int cb[NB];

  for (i = 0; i < NB; i++) {
    cb[i] = 0;
    for (j = 3; j >= 0; j--) {
      cb[i] = (cb[i] << 8) | ((data[(i + j) & 3] >> (j * 8)) & 0xff);
    }
  }

  for (i = 0; i < NB; i++) {
    data[i] = cb[i];
  }
}

/************************************************************/
/* Inverse ShiftRows: derived to invert the above ShiftRows */
void InvShiftRows(int *data)
{
  int i;
  int out[NB];

  #define GET_BYTE(word, b) ((unsigned char)(((word) >> ((b) * 8)) & 0xff))

  for (i = 0; i < NB; i++) {
    unsigned char b3 = GET_BYTE(data[(i + 1) & 3], 3);
    unsigned char b2 = GET_BYTE(data[(i + 2) & 3], 2);
    unsigned char b1 = GET_BYTE(data[(i + 3) & 3], 1);
    unsigned char b0 = GET_BYTE(data[i], 0);

    out[i] = ((int)b3 << 24) | ((int)b2 << 16) | ((int)b1 << 8) | (int)b0;
  }

  for (i = 0; i < NB; i++) {
    data[i] = out[i];
  }

  #undef GET_BYTE
}

/************************************************************/
/* FIPS 197 P.10 4.2 multiplication in GF(2^8) */
// cyber func=combinational_operator
int mul(int dt, int n)
{
  int i, x = 0;
  for (i = 8; i > 0; i >>= 1) {
    x <<= 1;
    if (x & 0x100)
      x = (x ^ 0x1b) & 0xff;
    if ((n & i))
      x ^= dt;
  }
  return x;
}

/************************************************************/
int dataget(int *data, int n)
{
  int ret;

  ret = (data[(n >> 2)] >> ((n & 0x3) * 8)) & 0xff;
  return ret;
}

/************************************************************/
/* FIPS 197  P.18 Figure 9 */
void MixColumns(int *data)
{
  int i, i4, x;

  for (i = 0; i < NB; i++) {
    i4 = i * 4;
    x  =  mul(dataget(data, i4 + 0), 2) ^
          mul(dataget(data, i4 + 1), 3) ^
          mul(dataget(data, i4 + 2), 1) ^
          mul(dataget(data, i4 + 3), 1);
    x |= (mul(dataget(data, i4 + 1), 2) ^
          mul(dataget(data, i4 + 2), 3) ^
          mul(dataget(data, i4 + 3), 1) ^
          mul(dataget(data, i4 + 0), 1)) << 8;
    x |= (mul(dataget(data, i4 + 2), 2) ^
          mul(dataget(data, i4 + 3), 3) ^
          mul(dataget(data, i4 + 0), 1) ^
          mul(dataget(data, i4 + 1), 1)) << 16;
    x |= (mul(dataget(data, i4 + 3), 2) ^
          mul(dataget(data, i4 + 0), 3) ^
          mul(dataget(data, i4 + 1), 1) ^
          mul(dataget(data, i4 + 2), 1)) << 24;
    data[i] = x;
  }
}

/************************************************************/
/* Inverse MixColumns (using standard AES inverse matrix) */
void InvMixColumns(int *data)
{
  int i, i4, x;

  for (i = 0; i < NB; i++) {
    i4 = i * 4;

    int b0 = dataget(data, i4 + 0);
    int b1 = dataget(data, i4 + 1);
    int b2 = dataget(data, i4 + 2);
    int b3 = dataget(data, i4 + 3);

    x  =  mul(b0, 14) ^ mul(b1, 11) ^ mul(b2, 13) ^ mul(b3, 9);
    x |= (mul(b0,  9) ^ mul(b1, 14) ^ mul(b2, 11) ^ mul(b3,13)) << 8;
    x |= (mul(b0, 13) ^ mul(b1,  9) ^ mul(b2, 14) ^ mul(b3,11)) << 16;
    x |= (mul(b0, 11) ^ mul(b1, 13) ^ mul(b2,  9) ^ mul(b3,14)) << 24;

    data[i] = x;
  }
}

/************************************************************/
/* FIPS 197  P.19 Figure 10 */
void AddRoundKey(int *data, int n)
{
  int i;

  for (i = 0; i < NB / 2; i++) {
    data[i * 2    ] ^= w[i * 2    + NB * n];
    data[i * 2 + 1] ^= w[i * 2 + 1 + NB * n];
  }
}

/************************************************************/
/* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
int SubWord(int word)
{
  int inw = word;
  int i;

  for (i = 3; i >= 0; i--) {
    inw = (inw << 8) | Sbox[(word >> (8 * i)) & 0xff];
  }

  return inw;
}

/************************************************************/
/* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
int RotWord(int word)
{
  int inw = word, inw2 = 0;

  inw2 = ((inw & 0xff) << 24) | ((inw >> 8) & 0x00ffffff);
  return inw2;
}

/************************************************************/
/* FIPS 197  P.20 Figure 11 */
void KeyExpansion(unsigned char *key)
{
  int Rcon[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
  int i, temp;
  int j;
  int wrk;

  for (i = 0; i < nk * 4 / 4; i++) {
    wrk = 0;
    for (j = 3; j >= 0; j--) {
      wrk = (wrk << 8) | key[i * 4 + j];
    }
    w[i] = wrk;
  }

  wrk = w[3];

  for (i = nk; i < NB * (nr + 1); i++) {
    temp = wrk;

    if ((i % nk) == 0)
      temp = SubWord(RotWord(temp)) ^ Rcon[(i / nk) - 1];

    temp ^= w[i - nk];
    wrk   = temp;
    w[i]  = temp;
  }
}

/************************************************************/
int aes_encrypt(unsigned char *key, int *data)
{
  KeyExpansion(key);
  Cipher(data);
  return 1;
}

int aes_decrypt(unsigned char *key, int *data)
{
  KeyExpansion(key);   /* deterministic; OK to recompute */
  InvCipher(data);
  return 1;
}

/************************************************************/
int main(void)
{
  int i;
  unsigned char plaintext[17] = {0};//array of 17 bytes Each 1 byte (8 bits)1 byte is reserved for the string null terminator '\0'
  unsigned char block[16] = {0}; // Creates a 16-byte buffer
  unsigned char decrypted[17] = {0};
  unsigned char fpga_decrypted[17] = {0};   // for FPGA decrypt result

  uint32_t w[4];// for plaintext
  uint32_t c0, c1, c2, c3;// for key
  int cipher_state[NB];
    unsigned char cipher_bytes[16];

   void *virtual_base;
    int fd;

    // Addresses for HEX displays
    volatile uint32_t *ENC0_addr;
	volatile uint32_t *ENC1_addr;
    volatile uint32_t *ENC2_addr;
	volatile uint32_t *ENC3_addr;
	volatile uint32_t *KEY0_addr;
	volatile uint32_t *KEY1_addr;
    volatile uint32_t *KEY2_addr;
	volatile uint32_t *KEY3_addr;
	volatile uint32_t *IN0_addr;
    volatile uint32_t *IN1_addr;
    volatile uint32_t *IN2_addr;
    volatile uint32_t *IN3_addr;
	volatile uint32_t *CTRL_addr;
volatile uint32_t *STATUS_addr;
    

    // map the address space for the HEX registers into user space so we can interact with them.
    // we'll actually map in the entire CSR span of the HPS since we want to access various registers within that span

    if( ( fd = open( "/dev/mem", ( O_RDWR | O_SYNC ) ) ) == -1 ) {
        printf( "ERROR: could not open \"/dev/mem\"...\n" );
        return( 1 );
    }

    virtual_base = mmap( NULL, HW_REGS_SPAN, ( PROT_READ | PROT_WRITE ), MAP_SHARED, fd, HW_REGS_BASE );

    if( virtual_base == MAP_FAILED ) {
        printf( "ERROR: mmap() failed...\n" );
        close( fd );
        return( 1 );
    }

    // Map HEX PIOs (names now match hps_0.h: HEX0_BASE..HEX5_BASE)
    ENC0_addr = virtual_base +
        ( (unsigned long)(ALT_LWFPGASLVS_OFST + ENC0_BASE) & (unsigned long)(HW_REGS_MASK) );
    ENC1_addr = virtual_base +
        ( (unsigned long)(ALT_LWFPGASLVS_OFST + ENC1_BASE) & (unsigned long)(HW_REGS_MASK) );
    ENC2_addr = virtual_base +
        ( (unsigned long)(ALT_LWFPGASLVS_OFST + ENC2_BASE) & (unsigned long)(HW_REGS_MASK) );
    ENC3_addr = virtual_base +
        ( (unsigned long)(ALT_LWFPGASLVS_OFST + ENC3_BASE) & (unsigned long)(HW_REGS_MASK) );
	KEY0_addr = virtual_base +
        ( (unsigned long)(ALT_LWFPGASLVS_OFST + KEY0_BASE) & (unsigned long)(HW_REGS_MASK) );
    KEY1_addr = virtual_base +
        ( (unsigned long)(ALT_LWFPGASLVS_OFST + KEY1_BASE) & (unsigned long)(HW_REGS_MASK) );
	KEY2_addr = virtual_base +
        ( (unsigned long)(ALT_LWFPGASLVS_OFST + KEY2_BASE) & (unsigned long)(HW_REGS_MASK) );
    KEY3_addr = virtual_base +
        ( (unsigned long)(ALT_LWFPGASLVS_OFST + KEY3_BASE) & (unsigned long)(HW_REGS_MASK) );
	IN0_addr = virtual_base +
        ( (unsigned long)(ALT_LWFPGASLVS_OFST + IN0_BASE) & (unsigned long)(HW_REGS_MASK) );
    IN1_addr = virtual_base +
        ( (unsigned long)(ALT_LWFPGASLVS_OFST + IN1_BASE) & (unsigned long)(HW_REGS_MASK) );
	IN2_addr = virtual_base +
        ( (unsigned long)(ALT_LWFPGASLVS_OFST + IN2_BASE) & (unsigned long)(HW_REGS_MASK) );
    IN3_addr = virtual_base +
        ( (unsigned long)(ALT_LWFPGASLVS_OFST + IN3_BASE) & (unsigned long)(HW_REGS_MASK) );
	CTRL_addr = virtual_base +
        ( (unsigned long)(ALT_LWFPGASLVS_OFST + CTRL_BASE) & (unsigned long)(HW_REGS_MASK) );
	STATUS_addr = virtual_base +
        ( (unsigned long)(ALT_LWFPGASLVS_OFST + STATUS_BASE) & (unsigned long)(HW_REGS_MASK) );	
		  /* Initialize inverse S-box */
  init_inv_sbox();
*CTRL_addr = 0x0;        // start=0
BARRIER();

  srand((unsigned int)time(NULL));
  for (i = 0; i < 16; i++) {
    key[i] = (unsigned char)(rand() & 0xff);
  }
c0 = ((uint32_t)key[0] << 24) |
     ((uint32_t)key[1] << 16) |
     ((uint32_t)key[2] <<  8) |
     ((uint32_t)key[3]      );

c1 = ((uint32_t)key[4] << 24) |
     ((uint32_t)key[5] << 16) |
     ((uint32_t)key[6] <<  8) |
     ((uint32_t)key[7]      );

c2 = ((uint32_t)key[8] << 24) |
     ((uint32_t)key[9] << 16) |
     ((uint32_t)key[10] << 8) |
     ((uint32_t)key[11]      );

c3 = ((uint32_t)key[12] << 24) |
     ((uint32_t)key[13] << 16) |
     ((uint32_t)key[14] << 8) |
     ((uint32_t)key[15]      );
*KEY0_addr = c3;
*KEY1_addr = c2;
*KEY2_addr = c1;
*KEY3_addr = c0;
BARRIER();


  /* 2) Read user input (plaintext) via scanf (up to 16 chars) */
  printf("Enter plaintext (max 16 ASCII characters, no spaces): ");//Reads up to 16 characters into plaintext
  scanf("%16s", (char *)plaintext);	//,%s stops at space.It adds a null terminator '\0' after the characters if user types: hi plaintext = { 'h','i','\0', ... }
  
/* Copy into 16-byte block (pad with zeros if shorter) */
  memset(block, 0, sizeof(block));
  for (i = 0; i < 16 && plaintext[i] != '\0'; i++) {
    block[i] = plaintext[i];
  }  
for (i = 0; i < 4; i++) {//Pack 16 bytes (blocks) into 4 words (32-bit each)
        int idx = 4 * i;
		w[i] =  ((uint32_t)block[idx + 0]<< 24)
                  | ((uint32_t)block[idx + 1] << 16)
                  | ((uint32_t)block[idx + 2] << 8)
                  | ((uint32_t)block[idx + 3] );
				  
    }  
   
*IN0_addr = w[3];
*IN1_addr = w[2];
*IN2_addr = w[1];
*IN3_addr = w[0];
BARRIER();


*CTRL_addr = 0x1;   // bit0 = start
BARRIER();
*CTRL_addr = 0x0;
BARRIER();

while(((*STATUS_addr) & 0x2) == 0) {
usleep(100);}
uint32_t e0 = *ENC0_addr;
uint32_t e1 = *ENC1_addr;
uint32_t e2 = *ENC2_addr;
uint32_t e3 = *ENC3_addr;

uint8_t FPGA_ciphertext[16];

FPGA_ciphertext[0]  = (e3 >> 24) & 0xFF;  
FPGA_ciphertext[1]  = (e3 >> 16) & 0xFF;
FPGA_ciphertext[2]  = (e3 >>  8) & 0xFF;
FPGA_ciphertext[3]  =  e3        & 0xFF;  

FPGA_ciphertext[4]  = (e2 >> 24) & 0xFF;
FPGA_ciphertext[5]  = (e2 >> 16) & 0xFF;
FPGA_ciphertext[6]  = (e2 >>  8) & 0xFF;
FPGA_ciphertext[7]  =  e2        & 0xFF;

FPGA_ciphertext[8]  = (e1 >> 24) & 0xFF;
FPGA_ciphertext[9]  = (e1 >> 16) & 0xFF;
FPGA_ciphertext[10] = (e1 >>  8) & 0xFF;
FPGA_ciphertext[11] =  e1       & 0xFF;

FPGA_ciphertext[12] = (e0 >> 24) & 0xFF;
FPGA_ciphertext[13] = (e0 >> 16) & 0xFF;
FPGA_ciphertext[14] = (e0 >>  8) & 0xFF;
FPGA_ciphertext[15] =  e0        & 0xFF;  


bytes_to_state(FPGA_ciphertext, data);
aes_decrypt(key, data);
state_to_bytes(data, fpga_decrypted);
fpga_decrypted[16] = '\0';


  /* Map bytes -> AES state (int data[4]) */
  bytes_to_state(block, data);

  /* 3) Encrypt */
  aes_encrypt(key, data);

  /* Save ciphertext state for printing */
  for (i = 0; i < NB; i++) {
    cipher_state[i] = data[i];
  }
  state_to_bytes(cipher_state, cipher_bytes);


  /* 3) Decrypt */
  aes_decrypt(key, data);

  /* Map state back to bytes */
  state_to_bytes(data, decrypted);
  decrypted[16] = '\0';  /* ensure null-terminated string */

  
  printf("\n");

  printf("\nEncryption Key: ");//Prints a label (and a newline before it).
  for (i = 0; i < 16; i++) printf("%02X", key[i]);//Loops through key[0] ... key[15],%02X means X = print in hex, 2 = width 2 characters
  printf("\n");//key = {0xBD,0xD7,0x59,0xC3, ... } when print KEY (16 bytes hex)       = BDD759C
printf("Original plaintext: %s\n", plaintext);

printf("Ciphertext from FPGA: ");
for (int i = 0; i < 16; i++) {
    printf("%02X", FPGA_ciphertext[i]);//from fpga
}
printf("\n");
printf("SW decrypted Plaintext(from FPGA Cphertext): %s\n", decrypted);

printf("SW encrypted: ");
  for (i = 0; i < 16; i++) printf("%02X", cipher_bytes[i]);
  printf("\n");
  
  return 0;
}

