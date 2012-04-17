CC = gcc
CFLAGS =-g
OBJS = dnsfunctions.o

all:	dnsfunctions.o
	${CC} ${CFLAGS} -o nresolver nresolver.c ${OBJS}
	${CC} ${CFLAGS} -o nserver nserver.c ${OBJS}

dnsfunctions.o:	dnsfunctions.c
	${CC} ${CFLAGS} -c -o dnsfunctions.o dnsfunctions.c

clean:
	rm -f *.o nresolver nserver
