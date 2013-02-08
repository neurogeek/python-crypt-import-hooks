/*
 * CryptImpHook_Conv.c
 *
 *  Created on: Jul 16, 2011
 *  Author: Jesus Rivero (Neurogeek) <neurogeekster@gmail.com>
 *                                   <neurogeek@gentoo.org>
 *
 * CryptImpHook_Conv is a program to encrypt a file using a XOR cipher.
 * This is part of the CPython CryptImpHook proof-of-concept
 *
 * LGPL-2.1. The license and distribution terms for this file may be
 * found in the file LICENSE in this distribution or at
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "CryptImpHook.h"
#include "Cipher.h"

/*!
 * \brief Reads a file and creates another one XOR'ing the contents of the first.
 * \param in (FILE *) The in file which contents are going to be XOR'red.
 * \param out (FILE *) The results are going to be in this file.
 * \param key (char *) The key used to XOR.
 */
void encrypt_data(FILE* in, FILE* out, char* key)
{
	int idx = 0; 
	int btoenc;
	
	while( (btoenc = fgetc(in)) != EOF) 
	{
		fputc(XOR(btoenc, key[idx % strlen(key)]), out);
		idx++;
	}
}

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		printf("Usage: %s <infile> <outfile>\n", argv[0]);
		exit(0);
	}
	
	FILE* in;
	FILE* out;

	in = fopen(argv[1], "r");
	out = fopen(argv[2], "w");

	if (in == NULL)
	{
		printf("Input file cannot be read.\n");
		exit(0);
	}
		
	if (out == NULL)
	{
		printf("Output file cannot be written to.\n");
		exit(0);
	}

	printf("Encrypting %s\n", argv[1]);
	encrypt_data(in, out, qta);
	printf("Encrypted data written to %s\n", argv[2]);

	fclose(in);
	fclose(out);

	return 0;
}
