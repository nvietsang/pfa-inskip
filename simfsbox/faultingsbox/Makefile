CFLAGS	?= -O2

main: main.c aes.h
	$(CC) $(CFLAGS) main.c -o $@
	
clean:
	rm -f main
	rm -f *.o
	rm -f *.txt