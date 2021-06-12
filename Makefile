all: build 
build:
	 gcc -m32 main.c -o demo_elf
	 
run:
	./demo_elf
test:
	echo "A to sploh dela?"
clean:
	rm -f demo_elf
