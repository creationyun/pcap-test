LDLIBS = -lpcap

all: pcap-test

pcap-test: protocol.o main.o
	$(CXX) protocol.o main.o -o pcap-test $(LDLIBS)

protocol.o: protocol.cpp

main.o: main.cpp

clean:
	rm -f pcap-test *.o

