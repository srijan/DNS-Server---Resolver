#include "ndns.h"

struct gethost_reply {
  int type;             /* -1: Not found, 0: Found IP, 1: Found nameserver */
  char details[100];
};
typedef struct gethost_reply ghreply;
ghreply ngethostbyname(unsigned char *, unsigned char *, int, int);
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
unsigned char* ReadName (unsigned char*,unsigned char*,int*);
