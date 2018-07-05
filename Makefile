ifeq ($(OS),Windows_NT)
	EXE_SUFFIX = .exe
endif

all: armbin2elf$(EXE_SUFFIX)

armbin2elf$(EXE_SUFFIX): Makefile armbin2elf.c
	gcc armbin2elf.c -o $@ $(CFLAGS)
	strip $@

clean:
	rm -f armbin2elf$(EXE_SUFFIX)
