CC = gcc
CFLAGS = -std=c17 -Wall -Wextra -Werror -D_GNU_SOURCE

EXECUTABLE = ipk-l4-scan
LOGIN = xpazurm00

all: $(EXECUTABLE)
	@echo "Project compiled successfuly!"

$(EXECUTABLE): $(wildcard *.c)
	$(CC) $(CFLAGS) -o $@ $^

%o : %c
	$(CC) $(CFLAGS) -c $<

run:
	@./$(EXECUTABLE)

clean:
	rm -f *.o $(EXECUTABLE)

zip:
	zip $(LOGIN).zip *.c *.h README.md Makefile CHANGELOD.md

.PHONY: all run clean
