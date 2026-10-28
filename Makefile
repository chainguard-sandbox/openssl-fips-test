PROG = openssl-fips-test
SRCS = openssl-fips-test.c
CFLAGS += -Wall -std=gnu1x -O3 -D_FORTIFY_SOURCE=3
CFLAGS += $(shell pkg-config --cflags libcrypto)
INSTALL ?= install
LIBS = -ldl
OBJS = ${SRCS:.c=.o}

all: ${PROG}

${PROG}: ${OBJS}
	${CC} -o $@ ${OBJS} ${LIBS}

clean:
	rm ${OBJS} ${PROG}

install:
	${INSTALL} -Dm755 ${PROG} ${DESTDIR}/usr/bin/${PROG}

.DUMMY: clean
