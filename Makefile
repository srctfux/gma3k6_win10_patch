CPP      = g++.exe
CC       = gcc.exe
WINDRES  = windres.exe
RES      = obj/resource.res
OBJ      = obj/main.o obj/patch.o obj/crc32.o $(RES)
LINKOBJ  = $(OBJ)
LIBS     = -static-libgcc -Wl,--gc-sections -mwindows -lcomctl32 -lshlwapi -lversion -m32 -s
INCS     = -I"./src" -I"./res"
CXXINCS  = $(INCS)
BIN      = patch.exe
CXXFLAGS = $(CXXINCS) -O2 -m32 -std=c99 -Wall -Wextra -pedantic -Wfatal-errors -ffunction-sections -fdata-sections -flto
CFLAGS   = $(INCS) -O2 -m32 -std=c99 -Wall -Wextra -pedantic -Wfatal-errors -ffunction-sections -fdata-sections -flto
RM       = rm.exe -f

.PHONY: all all-before all-after clean clean-custom

all: all-before $(BIN) all-after

clean: clean-custom
	${RM} $(OBJ) $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LINKOBJ) -o $(BIN) $(LIBS)

obj/main.o: src/main.c
	$(CC) -c src/main.c -o obj/main.o $(CFLAGS)

obj/patch.o: src/patch.c
	$(CC) -c src/patch.c -o obj/patch.o $(CFLAGS)

obj/crc32.o: src/crc32.c
	$(CC) -c src/crc32.c -o obj/crc32.o $(CFLAGS)

obj/resource.res: res/resource.rc 
	$(WINDRES) -i res/resource.rc -F pe-i386 --input-format=rc -o obj/resource.res -O coff  --include-dir ./res
