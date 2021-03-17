/**
 *  tunnel.c
 */

#include "icmp.h"
#include "tunnel.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>


#define DEFAULT_ROUTE   "0.0.0.0"

/**
 * Function to allocate a tunnel
 */
int tun_alloc(char *dev, int flags)
{
  struct ifreq ifr;
  int tun_fd, err;
  char *clonedev = "/dev/net/tun";
  printf("[DEBUG] Allocating tunnel\n");

  tun_fd = open(clonedev, O_RDWR);

  if(tun_fd == -1) {
    perror("Unable to open clone device\n");
    exit(EXIT_FAILURE);
  }
  
  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if ((err=ioctl(tun_fd, TUNSETIFF, (void *)&ifr)) < 0) {
    close(tun_fd);
    fprintf(stderr, "Error returned by ioctl(): %s\n", strerror(err));
    perror("Error in tun_alloc()\n");
    exit(EXIT_FAILURE);
  }

  printf("[DEBUG] Allocatating tunnel2\n");

  printf("[DEBUG] Created tunnel %s\n", dev);

  return tun_fd;
}

/**
 * Function to read from a tunnel
 */
int tun_read(int tun_fd, char *buffer, int length)
{
  int bytes_read;
  printf("[DEBUG] Reading from tunnel\n");
  bytes_read = read(tun_fd, buffer, length);

  if (bytes_read == -1) {
    perror("Unable to read from tunnel\n");
    exit(EXIT_FAILURE);
  }
  else {
    return bytes_read;
  }
}

/**
 * Function to write to a tunnel
 */
int tun_write(int tun_fd, char *buffer, int length)
{
  int bytes_written;
  printf("[DEBUG] Writing to tunnel\n");
  bytes_written = write(tun_fd, buffer, length);

  if (bytes_written == -1) {
    perror("Unable to write to tunnel\n");
    exit(EXIT_FAILURE);
  }
  else {
    return bytes_written;
  }
}

/**
 * Function to configure the network
 */
void configure_network(int server)
{
  int pid, status;
  char path[100];
  char *const args[] = {path, NULL};

  if (server) {
    if (sizeof(SERVER_SCRIPT) > sizeof(path)){
      perror("Server script path is too long\n");
      exit(EXIT_FAILURE);
    }
    strncpy(path, SERVER_SCRIPT, strlen(SERVER_SCRIPT) + 1);
  }
  else {
    if (sizeof(CLIENT_SCRIPT) > sizeof(path)){
      perror("Client script path is too long\n");
      exit(EXIT_FAILURE);
    }
    strncpy(path, CLIENT_SCRIPT, strlen(CLIENT_SCRIPT) + 1);
  }

  pid = fork();

  if (pid == -1) {
    perror("Unable to fork\n");
    exit(EXIT_FAILURE);
  }
  
  if (pid==0) {
    // Child process, run the script
    exit(execv(path, args));
  }
  else {
    // Parent process
    waitpid(pid, &status, 0);
    if (WEXITSTATUS(status) == 0) {
      // Script executed correctly
      printf("[DEBUG] Script ran successfully\n");
    }
    else {
      // Some error
      printf("[DEBUG] Error in running script\n");
    }
  }
}

/**
 * Function to handshake.
 * identify server and client, to exchage client side's outgoing ip addess
 * server: standby
 * client: send a icmp echo, with payload=hash(*token)
 * server: reply a icmp reply, with payload=hash(*token)
 * server: modify dest as client's outgoing address
 */
void handshake(int sock_fd, char *dest, int server, char *token, char *client_addr) {
    struct icmp_packet packet;
    memset(&packet, 0, sizeof(packet));
    strncpy(packet.src_addr, DEFAULT_ROUTE, sizeof(packet.src_addr));
    strncpy(packet.dest_addr, dest, sizeof(packet.dest_addr));

    printf("[DEBUG] Starting handshake is_server=%d\n", server);
    if (!server) {
        set_echo_type(&packet);
        packet.payload = token;
        packet.payload_size = strnlen(token,MTU);
        printf("[DEBUG] Send handshake echo. addr = %s, token = %s\n", dest, token);
        send_icmp_packet(sock_fd, &packet);

        while (1) {
            memset(&packet, 0, sizeof(struct icmp_packet));
            receive_icmp_packet(sock_fd, &packet);
            if ( strncmp(packet.src_addr,dest, sizeof(packet.src_addr)) != 0) {// ignore traffic 
                printf("[DEBUG] Received handshake. addr = %s(should %s), token = %s\n",
                        packet.src_addr, dest, packet.payload);
                reply_icmp(sock_fd, &packet);
                free(packet.payload);
                continue;
            }
            if ( strncmp(packet.payload, token, strlen(token)) != 0) { //token mismatch
                printf("[DEBUG] Received handshake. addr = %s, token = %s(should %s)\n",
                        packet.src_addr, packet.payload, token);
                reply_icmp(sock_fd, &packet);
                free(packet.payload);
                continue;
            }
            printf("[DEBUG] Received handshake. addr = %s, token = %s. Succ!\n",packet.src_addr, token);
            free(packet.payload);
            break;
        }
    } else {  // server mode
        while (1) {
            memset(&packet, 0, sizeof(packet));
            receive_icmp_packet(sock_fd, &packet);
            if ( strncmp(packet.payload, token, strlen(token)) != 0) { //token mismatch
                printf("[DEBUG] Received handshake. addr = %s, token = %s(should %s)\n",packet.src_addr, packet.payload, token);
                reply_icmp(sock_fd, &packet);
                free(packet.payload);
                continue;
            }
            printf("[DEBUG] Received handshake. addr = %s, token = %s. Succ! Reply it\n",packet.src_addr, token);
            memcpy(client_addr, packet.src_addr, strlen(packet.src_addr)+1);

            reply_icmp(sock_fd, &packet);
            free(packet.payload);

            break;
        }
    }
}
/**
 * Function to run the tunnel
 */
void run_tunnel(char *dest, int server, char *token, char *tun_interface)
{
  struct icmp_packet packet;
  int tun_fd, sock_fd;
  char client_addr[100] = {0};
  uint16_t icmp_id = 0;

  fd_set fs;

  tun_fd = tun_alloc(tun_interface, IFF_TUN | IFF_NO_PI);
  printf("[DEBUG] Allocated the tunnel interface = %s\n", tun_interface);

  printf("[DEBUG] Starting tunnel - Dest: %s, Server: %d\n", dest, server);
  printf("[DEBUG] Opening ICMP socket\n");
  sock_fd = open_icmp_socket();

  if (server) {
    printf("[DEBUG] Binding ICMP socket\n");
    bind_icmp_socket(sock_fd);
  }

  configure_network(server);
  handshake(sock_fd, dest, server, token, client_addr); // in server mode, client_addr will be filled with cliet's outgoing addr
  if(server)
      memcpy(dest, client_addr, strlen(client_addr)+1);

  while (1) {
    FD_ZERO(&fs);
    FD_SET(tun_fd, &fs);
    FD_SET(sock_fd, &fs);

    select(tun_fd>sock_fd?tun_fd+1:sock_fd+1, &fs, NULL, NULL, NULL);

    // tunnel package arrived, usually userspace app. (from virtual network)
    if (FD_ISSET(tun_fd, &fs)) {
      printf("[DEBUG] Data needs to be readed from tun device\n");
      // Reading data from tun device and sending ICMP packet

      printf("[DEBUG] Preparing ICMP packet to be sent\n");
      // Preparing ICMP packet to be sent
      memset(&packet, 0, sizeof(packet));
      printf("[DEBUG] Destination address: %s\n", dest);

      if (sizeof(DEFAULT_ROUTE) > sizeof(packet.src_addr)){
        perror("Lack of space: size of DEFAULT_ROUTE > size of src_addr\n");
        close(tun_fd);
        close(sock_fd);
        exit(EXIT_FAILURE);
      }
      strncpy(packet.src_addr, DEFAULT_ROUTE, strlen(DEFAULT_ROUTE) + 1);

      if ((strlen(dest) + 1) > sizeof(packet.dest_addr)){
        perror("Lack of space for copy size of DEFAULT_ROUTE > size of dest_addr\n");
        close(sock_fd);
        exit(EXIT_FAILURE);
      }
      strncpy(packet.dest_addr, dest, strlen(dest) + 1);

      if(server) {
        packet.id = icmp_id;
        set_reply_type(&packet);
      }
      else {
        set_echo_type(&packet);
      }
      packet.payload = calloc(MTU, sizeof(uint8_t));
      if (packet.payload == NULL){
        perror("No memory available\n");
        exit(EXIT_FAILURE);
      }

      packet.payload_size  = tun_read(tun_fd, packet.payload, MTU);
      if(packet.payload_size  == -1) {
        perror("Error while reading from tun device\n");
        exit(EXIT_FAILURE);
      }

      printf("[DEBUG] Sending ICMP packet from %s to %s with payload_size: %d, payload: %s\n",
              packet.src_addr, packet.dest_addr,  packet.payload_size, packet.payload);
      // Sending ICMP packet
      send_icmp_packet(sock_fd, &packet);

      free(packet.payload);
    }

    // icmp package arrived. (from real network)
    if (FD_ISSET(sock_fd, &fs)) {
      // Getting ICMP packet
      memset(&packet, 0, sizeof(struct icmp_packet));
      receive_icmp_packet(sock_fd, &packet);

      printf("[DEBUG] Read ICMP packet with id:%d, src: %s, dest: %s, payload_size: %d, payload hdr_ver:IPv%d, payload: %s\n",
              ntohs(packet.id),  packet.src_addr, packet.dest_addr, packet.payload_size, ((struct iphdr*)packet.payload)->version, packet.payload);
      if ((server && strncmp(packet.src_addr, client_addr, sizeof(client_addr))) || 
              (!server && strncmp(packet.src_addr, dest, sizeof(packet.src_addr))) )// peer ip not match
      {
          printf("[WARN] illegal source : %s(should %s)\n", packet.src_addr, server?client_addr:dest);
          //reply_icmp(sock_fd, &packet);
          free(packet.payload);
          continue;
      }
      if (((struct iphdr*)packet.payload)->version != 4) { // not illegal ipv4 packet
          printf("[WARN] illegal packet version : ipv%d. should be 4 or 6\n", ((struct iphdr*)packet.payload)->version);
          //reply_icmp(sock_fd, &packet);
          free(packet.payload);
          continue;
      }
      // Writing out to tun device
      tun_write(tun_fd, packet.payload, packet.payload_size);

      //printf("[DEBUG] Src address being copied: %s\n", packet.src_addr);
      //strncpy(dest, packet.src_addr, strlen(packet.src_addr) + 1);
      icmp_id = packet.id;
      free(packet.payload);
    }
  }

}
