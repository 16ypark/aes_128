// 20160809 박유화
// 코드 environment, requirement
// This assignment is built on an open source specified below.
// aes.c, aes.h, main.c, makefile are included in the submission

/*
 *
 * Chinese Academy of Sciences
 * State Key Laboratory of Information Security
 * Institute of Information Engineering
 *
 * Copyright (C) 2016 Chinese Academy of Sciences
 *
 * LuoPeng, luopeng@iie.ac.cn
 * Updated in May 2016
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>

#include "aes.h"

// This is a record of number of 1s in 4-bit bynary numbers (0b0001, ..., 0b1111).
int num_to_bits[16] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };

// This function counts the number of 1s in a binary number t.
uint8_t countsetbits(uint8_t t) {
    if (t == 0) return num_to_bits[0];
    
    int tail = t & 0xf;
    return num_to_bits[tail] + countsetbits(t >> 4);
}

// This function gets the hamming distance between two numbers in form of array of bytes by using countsetbits function.
uint8_t gethamdist(uint8_t *a, uint8_t *b) {
    uint8_t c = 0;
    // for each byte
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        c += countsetbits(a[i] ^ b[i]);
    }
    return c;
}

/* This function does the parts (i) and (ii) of the assignment.
 It was made as a function because it is repeated in parts (a) and (b) of the assignment. */
void doencrypt(uint8_t *roundkeys, uint8_t *ciphertext, uint8_t *newciphertext, uint8_t *plaintext, uint8_t *newplaintext, uint8_t *key, uint8_t **addroundkeys, uint8_t **newaddroundkeys, FILE *fptr) {
    uint8_t i, r;
    uint8_t num, idx, bit_idx, b;
    
    // print PT
    fprintf(fptr, "PT = ");
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        fprintf(fptr, "%.2X", plaintext[i]);
    }
    fprintf(fptr, "\n");
    
    // print Key
    fprintf(fptr, "Key = ");
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        fprintf(fptr, "%.2X", key[i]);
    }
    fprintf(fptr, "\n");

    // key schedule
    aes_key_schedule_128(key, roundkeys);

    // encryption
    aes_encrypt_128(roundkeys, plaintext, ciphertext, addroundkeys);
    // print CT
    fprintf(fptr, "CT = ");
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        fprintf(fptr, "%.2X", ciphertext[i]);
    }
    fprintf(fptr, "\n");


    // decryption
    aes_decrypt_128(roundkeys, ciphertext, plaintext);
    // print decrypted ciphertext
    fprintf(fptr, "Decrypted = ");
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        fprintf(fptr, "%.2X", plaintext[i]);
    }
    fprintf(fptr, "\n\n");
    
    // generating random number
    num = rand() % 128;
    
    idx = num / 8;
    bit_idx = num % 8;
    // get the position of the bit to flip
    b = 1 << (7 - bit_idx);
    
    // if the bit is 0
    if ((newplaintext[idx] & b) == 0) {
        newplaintext[idx] |= b;
    // else if the bit is 1
    } else {
        newplaintext[idx] &= ~b;
    }
    
    // get the hamming distance for each rounds
    fprintf(fptr, "Hamming distance when %dth bit is changed\n\n", num + 1);
    
    fprintf(fptr, "PT : ");
    
    fprintf(fptr, "%.2X ", gethamdist(plaintext, newplaintext));
    
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        fprintf(fptr, "%.2X", plaintext[i]);
    }
    fprintf(fptr, " ");
    
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        fprintf(fptr, "%.2X", newplaintext[i]);
    }
    fprintf(fptr, "\n");
    
    // encryption of the plaintext with a flipped bit
    aes_encrypt_128(roundkeys, newplaintext, newciphertext, newaddroundkeys);
    // for each round...
    for ( r = 0; r < 9; r++ ) {
        fprintf(fptr, "R%d : %.2X ", r + 1, gethamdist(addroundkeys[r], newaddroundkeys[r]));
        for (i = 0; i < AES_BLOCK_SIZE; i++) {
            fprintf(fptr, "%.2X", *(*(addroundkeys + r) + i));
        }
        fprintf(fptr, " ");
        for (i = 0; i < AES_BLOCK_SIZE; i++) {
            fprintf(fptr, "%.2X", *(*(newaddroundkeys + r) + i));
        }
        fprintf(fptr, "\n");
    }
    
    // final ciphertext
    fprintf(fptr, "CT : %.2X ", gethamdist(ciphertext, newciphertext));
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        fprintf(fptr, "%.2X", ciphertext[i]);
    }
    fprintf(fptr, " ");
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        fprintf(fptr, "%.2X", newciphertext[i]);
    }
    fprintf(fptr, "\n\n");

}

int main(int argc, char *argv[]) {
    uint8_t i, n;
    
    FILE *fptr;

    // create and open a file named output.txt to write to in the current directory
    fptr = fopen("output.txt","w");

    if (fptr == NULL)
    {
       printf("Error!");
       exit(1);
    }

    
    srand ( time(NULL) );

    /* Initialization before passing the parameters to doencrypt function. */
    
	/* 128 bit key */
	uint8_t key[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,

	};

	uint8_t plaintext[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	};

 
	uint8_t ciphertext[AES_BLOCK_SIZE];
    uint8_t newciphertext[AES_BLOCK_SIZE];

    uint8_t newplaintext[16];
    memcpy(newplaintext, plaintext, sizeof(plaintext));
    
	uint8_t roundkeys[AES_ROUND_KEY_SIZE];
    
    uint8_t **addroundkeys = (uint8_t**)calloc(9, sizeof(uint8_t*));
    uint8_t **newaddroundkeys = (uint8_t**)calloc(9, sizeof(uint8_t*));
    
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        *(addroundkeys + i) = (uint8_t*)calloc(16, sizeof(uint8_t));
        *(newaddroundkeys + i) = (uint8_t*)calloc(16, sizeof(uint8_t));
    }

    fprintf(fptr,"[a]\n");
    // call doencrypt for part [a]
    doencrypt(roundkeys, ciphertext, newciphertext, plaintext, newplaintext, key, addroundkeys, newaddroundkeys, fptr);
    
    // ---------------------------------------------------------------------------------------
    //[b]
    
    /* Initialization before passing the parameters to doencrypt function. */
    
    memset(roundkeys, 0, sizeof(roundkeys));
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(newciphertext, 0, sizeof(newciphertext));
    memset(plaintext, 0, sizeof(plaintext));
    memset(newplaintext, 0, sizeof(newplaintext));
    memset(key, 0, sizeof(key));
    
    for (i = 0; i < 9; i++) {
        free(*(addroundkeys + i));
        free(*(newaddroundkeys + i));
    }
    free(addroundkeys);
    free(newaddroundkeys);
    
    uint8_t **b_addroundkeys = (uint8_t**)calloc(9, sizeof(uint8_t*));
    uint8_t **b_newaddroundkeys = (uint8_t**)calloc(9, sizeof(uint8_t*));
    
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        *(b_addroundkeys + i) = (uint8_t*)calloc(16, sizeof(uint8_t));
        *(b_newaddroundkeys + i) = (uint8_t*)calloc(16, sizeof(uint8_t));
    }

    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        n = rand() % 256;
        plaintext[i] = n;
        n = rand() % 256;
        key[i] = n;
    }
    memcpy(newplaintext, plaintext, sizeof(plaintext));

    fprintf(fptr, "[b]\n");
    // call doencrypt function for part [b]
    doencrypt(roundkeys, ciphertext, newciphertext, plaintext, newplaintext, key, b_addroundkeys, b_newaddroundkeys, fptr);
    
    // close output.txt
    fclose(fptr);
	return 0;

}
