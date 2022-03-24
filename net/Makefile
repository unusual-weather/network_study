add-nbo : lihi.o add.o
	gcc -o add-bo lihi.o add.o

lihi.o : lihi.c
	gcc -c -o lihi.o lihi.c

add.o : add.c
	gcc -c -o add.o add.c

clean:
	rm *.o add-bo