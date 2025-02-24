CC = gcc
CFLAGS = -std=c17 -Wall -Wextra -Werror -D_GNU_SOURCE

EXECUTABLE = ipk-l4-scan

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

.PHONY: all run clean
