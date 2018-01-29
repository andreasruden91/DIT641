.PHONY: all
all: login passgen

login: login.c db.c shared.c
	gcc -g -Wall login.c db.c shared.c -lcrypt -o login

passgen: passgen.c shared.c db.c
	gcc -g -Wall passgen.c shared.c db.c -lcrypt -o passgen

.PHONY: clean
clean:
	rm login main.o
