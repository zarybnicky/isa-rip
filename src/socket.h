/**
 * ISA18: Tools for monitoring and sniffing RIP messages
 * FIT VUT Brno
 * Author: xzaryb00 - Jakub Zarybnický (xzaryb00)
 *
 * A utility for creating a RIP multicast socket
 */

#ifndef ISA_SOCKET_H
#define ISA_SOCKET_H

#include <net/if.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include "rip.h"
#include "utils.h"

int prepare_socket(const char *interface);

#endif /* ISA_SOCKET_H */
