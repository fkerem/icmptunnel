/**
 * icmp_tunnel.c
 */

#include "tunnel.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ARG_SERVER_MODE "-s"
#define ARG_CLIENT_MODE "-c"

void usage()
{
  printf("Wrong argument\n");
  fprintf(stdout,
          "usage: icmptunnel <-s|-c> serverip token tun-interface\n"
          "\t-s: server mode\n"
          "\t-c: client mode\n"
          "serverip: the server side internet ip address. in server mode, can be 0.0.0.0\n"
          "token: to identify client and server, and match them. len(token) < 128 Bytes\n"
          "tunnel interface to be created: tun0, tun1, ... < 10 bytes\n"
         );
}

int main(int argc, char *argv[])
{
  char ip_addr[100] = {0,};
  char token[128] = {0,};
  char tun_interface[10] = {0,};
  if ((argc < 5) || ((strlen(argv[2]) + 1) > sizeof(ip_addr)) || ((strlen(argv[3]) + 1) > sizeof(token)) || ((strlen(argv[4]) + 1) > sizeof(tun_interface))) {
    usage();
    exit(EXIT_FAILURE);
  }
  memcpy(ip_addr, argv[2], strlen(argv[2]) + 1);
  memcpy(token, argv[3], strlen(argv[3]) + 1);
  memcpy(tun_interface, argv[4], strlen(argv[4]) + 1);

  if (strncmp(argv[1], ARG_SERVER_MODE, strlen(argv[1])) == 0) {
    run_tunnel(ip_addr, 1, token, tun_interface);
  }
  else if (strncmp(argv[1], ARG_CLIENT_MODE, strlen(argv[1])) == 0) {
    run_tunnel(ip_addr, 0, token, tun_interface);
  }
  else {
    usage();
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}
