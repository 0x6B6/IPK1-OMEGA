CC = gcc
CFLAGS = -std=c17 -Wall -Wextra -Werror -D_GNU_SOURCE -Wpedantic

EXECUTABLE = ipk-l4-scan
LOGIN = xpazurm00

all: $(EXECUTABLE)
	@echo "Project compiled successfuly!"

$(EXECUTABLE): $(wildcard src/*.c)
	$(CC) $(CFLAGS) -o $@ $^

src/%o : src/%c
	$(CC) $(CFLAGS) -c $<

run:
	@./$(EXECUTABLE)

clean:
	rm -f *.o $(EXECUTABLE)

zip:
	zip $(LOGIN).zip *.c *.h README.md Makefile CHANGELOD.md

.PHONY: all run clean
