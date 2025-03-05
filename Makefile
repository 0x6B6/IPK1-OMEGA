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
	rm -f src/*.o $(EXECUTABLE)
	rm -rf tests/*_result

zip:
	zip $(LOGIN).zip src/ tests/ images/ README.md Makefile CHANGELOG.md

.PHONY: all run clean
