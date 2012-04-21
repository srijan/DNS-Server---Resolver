#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include "dnsfunctions.h"

char dns_server[20];

void print_response(ghreply);
char* get_nameserver(ghreply);

int main(int argc, char const *argv[])
{
  unsigned char hostname[100];
  char tmp_dns_server[20];
  int reqtype;
  ghreply res;
  if(argc < 4) {
    fprintf(stderr, "Usage:  %s <DNS Server> <Hostname>" 
        " <Iterative(0) / Recursive(1)>\n", argv[0]);
    exit(1);
  }
  strncpy(dns_server,argv[1],20);
  strncpy(hostname,argv[2],100);
  reqtype = atoi(argv[3]);
  if(reqtype == 1) {
    printf("\n*** Resolving %s using %s\n" , hostname, dns_server);
    res = ngethostbyname(hostname,dns_server,reqtype);
    hostname[strlen(hostname)-1] = '\0';
  }
  else {
    strncpy(tmp_dns_server,dns_server,20);
    res.ans_count = 0;
    while(1) {
      printf("\n*** Resolving %s using %s\n" , hostname, tmp_dns_server);
      res = ngethostbyname(hostname,tmp_dns_server,reqtype);
      hostname[strlen(hostname)-1] = '\0';
      if(res.rcode == 0) {
        if(res.ans_count == 0) {
          print_response(res);
          strncpy(tmp_dns_server,get_nameserver(res),20);
        }
        else {
          break;
        }
      }
      else {
        break;
      }
    }
  }
  print_response(res);
  return 0;
}

void print_response(ghreply res) {
  int i;
  struct sockaddr_in a;
  switch(res.rcode) {
    case 0:
      break;
    case 3:
      printf("\nNXDOMAIN: server can't find domain\n");
      break;
    default:
      printf("\nSome error\n");
      break;
  }
  printf("\nThe response contains : ");
  printf("\n %d Questions.",res.q_count);
  printf("\n %d Answers.",res.ans_count);
  printf("\n %d Authoritative Servers.",res.auth_count);
  printf("\n %d Additional records.\n",res.add_count);
  //print answers
  printf("\nAnswer Records : %d \n" , res.ans_count);
  for(i=0; i<res.ans_count; i++) {
    printf("Name : %s ",res.answers[i].name);

    if( ntohs(res.answers[i].resource->type) == T_A) {
      long *p;
      p=(long*)res.answers[i].rdata;
      a.sin_addr.s_addr=(*p);
      printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
    }

    if(ntohs(res.answers[i].resource->type)==5) {
      //Canonical name for an alias
      printf("has alias name : %s",res.answers[i].rdata);
    }
    printf("\n");
  }

  //print authorities
  printf("\nAuthoritive Records : %d \n" , res.auth_count);
  for(i=0; i<res.auth_count; i++) {
    printf("Name : %s ",res.auth[i].name);
    if(ntohs(res.auth[i].resource->type)==2) {
      printf("has nameserver : %s",res.auth[i].rdata);
    }
    printf("\n");
  }

  //print additional resource records
  printf("\nAdditional Records : %d \n" , res.add_count);
  for(i=0; i<res.add_count; i++) {
    printf("Name : %s ",res.addit[i].name);
    if(ntohs(res.addit[i].resource->type)==1) {
      long *p;
      p=(long*)res.addit[i].rdata;
      a.sin_addr.s_addr=(*p);
      printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
    }
    printf("\n");
  }
}

char* get_nameserver(ghreply res) {
  char *nsip;
  nsip = (char*)malloc(sizeof(char)*20);
  char nsdomain[100];
  int i, flag;
  struct sockaddr_in a;
  ghreply tmp;

  flag = 0;
  if(res.add_count > 0) {
    for(i=0; i<res.add_count; i++) {
      if(ntohs(res.addit[i].resource->type)==1) {
        long *p;
        p=(long*)res.addit[i].rdata;
        a.sin_addr.s_addr=(*p);
        strncpy(nsip, inet_ntoa(a.sin_addr),20);
        flag = 1;
        break;
      }
    }
  }
  if(flag == 0) {
    for(i=0; i<res.auth_count; i++) {
      if(ntohs(res.auth[i].resource->type)==2) {
        strncpy(nsdomain,res.auth[i].rdata,100);
        tmp = ngethostbyname(nsdomain,dns_server,1);
        if(tmp.rcode == 0) {
          for(i=0; i<tmp.ans_count; i++) {
            if(ntohs(tmp.answers[i].resource->type) == T_A) {
              long *p;
              p=(long*)tmp.answers[i].rdata;
              a.sin_addr.s_addr=(*p);
              strncpy(nsip,inet_ntoa(a.sin_addr),20);
              flag = 1;
              break;
            }
          }
        }
        break;
      }
    }
  }
  if(flag == 0) {
    printf("Can't find domain. No answer.\n");
    exit(1);
  }
  return nsip;
}
