/**
 * ISA18: Tools for monitoring and sniffing RIP messages
 * FIT VUT Brno
 * Author: xzaryb00 - Jakub Zarybnický (xzaryb00)
 *
 * A program that multicasts a RIPng Response packet
 */

#ifndef ISA_MYRIPRESPONSE_H
#define ISA_MYRIPRESPONSE_H

#include <arpa/inet.h>
#include <stdio.h>
#include "socket.h"

int parse_number(const char *desc, const char *src, int lower, int upper);
int main(int argc, char *argv[]);

#endif /* ISA_MYRIPRESPONSE_H */
