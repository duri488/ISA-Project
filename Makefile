all: isa-tazatel.c 
	gcc -g -Wall -o isa-tazatel isa-tazatel.c -lresolv
clean: 
	$(RM) isa-tazatel