#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tboxes.h"


#define DW(t) (*(unsigned int*)(t))
#define ROR(a, n) ((a >> n) | ((a) << (32 - n)))
#define ROT(a) (ROR((a), 8))

#define BYTES_PER_LINE 16

void printBytes(const unsigned char* buffer, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("0x%02X, ", buffer[i]);
        if (i % BYTES_PER_LINE == BYTES_PER_LINE - 1) {
            printf("\n");
        }
    }
    if (len % BYTES_PER_LINE != 0) {
        printf("\n");
    }
}

void ShiftRows(unsigned char out[16])
{
        
    // +----+----+----+----+
    // | 00 | 04 | 08 | 12 |
    // +----+----+----+----+
    // | 01 | 05 | 09 | 13 |
    // +----+----+----+----+
    // | 02 | 06 | 10 | 14 |
    // +----+----+----+----+
    // | 03 | 07 | 11 | 15 |
    // +----+----+----+----+

    unsigned int i,k,s,tmp;

    for (i=1; i<4; i++) {
        s=0;

        while(s<i) {
            tmp=out[i];
            for(k=0; k<3; k++) {
                out[k*4+i]=out[k*4+i+4];
            }
            out[i+12]=tmp;
            s++;
        }
    }
}

void wbaes_ty(unsigned char in[16], unsigned char out[16])
{
    memcpy(out, in, 16);

    /// Let's start the encryption process now
    for (size_t i = 0; i < 9; ++i)
    {
        ShiftRows(out);

        for (size_t j = 0; j < 16; ++j)
        {
            unsigned char x = Tboxes[i][j][out[j]];
            out[j] = x;
        }
        
        for (size_t j = 0; j < 4; ++j)
        {
            unsigned char a = out[j * 4 + 0];
            unsigned char b = out[j * 4 + 1];
            unsigned char c = out[j * 4 + 2];
            unsigned char d = out[j * 4 + 3];

            DW(&out[j * 4]) = Ty[0][a] ^ Ty[1][b] ^ Ty[2][c] ^ Ty[3][d];
        }
    }

    /// Last round which is a bit different
    ShiftRows(out);

    for (size_t j = 0; j < 16; ++j)
    {
        unsigned char x = Tboxes[9][j][out[j]];
        out[j] = x;
    }
}

void wbaes_ty_xor(unsigned char in[16], unsigned char out[16])
{
    memcpy(out, in, 16);

    /// Let's start the encryption process now
    for (size_t i = 0; i < 9; ++i)
    {
        ShiftRows(out);

        for (size_t j = 0; j < 4; ++j)
        {
            unsigned char a = out[j * 4 + 0];
            unsigned char b = out[j * 4 + 1];
            unsigned char c = out[j * 4 + 2];
            unsigned char d = out[j * 4 + 3];

            a = out[j * 4 + 0] = Tboxes[i][j * 4 + 0][a];
            b = out[j * 4 + 1] = Tboxes[i][j * 4 + 1][b];
            c = out[j * 4 + 2] = Tboxes[i][j * 4 + 2][c];
            d = out[j * 4 + 3] = Tboxes[i][j * 4 + 3][d];

            unsigned int aa = Ty[0][a];
            unsigned int bb = Ty[1][b];
            unsigned int cc = Ty[2][c];
            unsigned int dd = Ty[3][d];

            out[j * 4 + 0] = (Xor[Xor[(aa >>  0) & 0xf][(bb >>  0) & 0xf]][Xor[(cc >>  0) & 0xf][(dd >>  0) & 0xf]])  | ((Xor[Xor[(aa >>  4) & 0xf][(bb >>  4) & 0xf]][Xor[(cc >>  4) & 0xf][(dd >>  4) & 0xf]]) << 4);
            out[j * 4 + 1] = (Xor[Xor[(aa >>  8) & 0xf][(bb >>  8) & 0xf]][Xor[(cc >>  8) & 0xf][(dd >>  8) & 0xf]])  | ((Xor[Xor[(aa >> 12) & 0xf][(bb >> 12) & 0xf]][Xor[(cc >> 12) & 0xf][(dd >> 12) & 0xf]]) << 4);
            out[j * 4 + 2] = (Xor[Xor[(aa >> 16) & 0xf][(bb >> 16) & 0xf]][Xor[(cc >> 16) & 0xf][(dd >> 16) & 0xf]])  | ((Xor[Xor[(aa >> 20) & 0xf][(bb >> 20) & 0xf]][Xor[(cc >> 20) & 0xf][(dd >> 20) & 0xf]]) << 4);
            out[j * 4 + 3] = (Xor[Xor[(aa >> 24) & 0xf][(bb >> 24) & 0xf]][Xor[(cc >> 24) & 0xf][(dd >> 24) & 0xf]])  | ((Xor[Xor[(aa >> 28) & 0xf][(bb >> 28) & 0xf]][Xor[(cc >> 28) & 0xf][(dd >> 28) & 0xf]]) << 4);
        }
    }

    /// Last round which is a bit different
    ShiftRows(out);

    for (size_t j = 0; j < 16; ++j)
    {
        unsigned char x = Tboxes[9][j][out[j]];
        out[j] = x;
    }
}

int main() {

    unsigned char key[16] = {
        0x61, 0x62, 0x63, 0x64,
        0x65, 0x66, 0x67, 0x68,
        0x69, 0x6A, 0x6B, 0x6C,
        0x6D, 0x6E, 0x6F, 0x70
    };

    unsigned char plaintext[16] = {
        0x61, 0x62, 0x63, 0x64,
        0x65, 0x66, 0x67, 0x68,
        0x69, 0x6A, 0x6B, 0x6C,
        0x6D, 0x6E, 0x6F, 0x70
    };

    unsigned char encrypted[16] = { 0 };

    wbaes_ty_xor(plaintext, encrypted);

    printBytes(encrypted, 16);

    return 0;
}