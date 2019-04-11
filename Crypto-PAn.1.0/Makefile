CC=g++
CFLAGS=-O4
FLAGS= 

TARGET=sample 

OBJS = rijndael.o panonymizer.o sample.o

.SUFFIXES: .cpp

all: $(TARGET) 

$(TARGET): $(OBJS) 
	$(CC) $(FLAGS) $(OBJS) -o $@ 

.cpp.o: 
	$(CC) -c $(CFLAGS) $< 

clean: 
	rm $(OBJS) $(TARGET) 
