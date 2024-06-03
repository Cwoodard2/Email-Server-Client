all:
	gcc -I /usr/include/openssl -lcrypto client3.c -o clientSender
	g++ clientReciever3.cpp -o clientReciever 
	gcc -I /usr/include/openssl -lcrypto serverboth10.c -o server

