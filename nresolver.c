#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include "dnsfunctions.h"

char dns_server[20];
int main(int argc, char const *argv[])
{
  unsigned char hostname[100];
  int reqtype;
  ghreply hostdetails, tmphd;
  hostdetails.type = -2;
  if(argc < 4) {
    fprintf(stderr, "Usage:  %s <DNS Server> <Hostname>" 
        "<Iterative(0) / Recursive(1)>\n", argv[0]);
    exit(1);
  }
  strncpy(dns_server,argv[1],20);
  strncpy(hostname,argv[2],100);
  reqtype = atoi(argv[3]);
  if(reqtype == 1) {
    hostdetails = ngethostbyname(hostname,dns_server,reqtype,1);
    hostname[strlen(hostname)-1] = '\0';
  }
  else {
    while(hostdetails.type == -2 || hostdetails.type == 1) {
      if(hostdetails.type == -2) {
        hostdetails = ngethostbyname(hostname,dns_server,0,1);
        hostname[strlen(hostname)-1] = '\0';
      }
      else {
        tmphd = ngethostbyname(hostdetails.details,dns_server,1,1);
        if(tmphd.type == -1) {
          hostdetails.type = -1;
          break;
        }
        hostdetails = ngethostbyname(hostname,tmphd.details,0,1);
        hostname[strlen(hostname)-1] = '\0';
      }
    }
  }
  printf("\n============================================\nFinal Answer:\n");
  switch(hostdetails.type) {
    case -1:
      printf("Host not found.\n");
      break;
    case 0:
      printf("Host %s has IP : %s\n", hostname, hostdetails.details);
      break;
  }
  return 0;
}

