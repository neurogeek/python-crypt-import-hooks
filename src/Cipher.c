/*
 * Cipher.c
 *
 *  Created on: Jul 16, 2011
 *  Author: Jesus Rivero (Neurogeek) <neurogeekster@gmail.com>
 *                                   <neurogeek@gentoo.org>
 *
 * LGPL-2.1. The license and distribution terms for this file may be
 * found in the file LICENSE in this distribution or at
 */

/*!
 * \brief Applies bitwise XOR to two chars.
 * \param btoenc (char) is the first element (a char from a plaintext.)
 * \param keybit (char) a char from the key.
 * \return XOR operation result.
 */
int XOR(char btoenc, char keybit)
{
    return btoenc ^ keybit;
}

