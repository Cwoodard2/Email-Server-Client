/*
** talker.c -- a datagram "client" demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdbool.h>


char *encodePassword(const unsigned char *plaintext, int length) {
  char *output = (char*) malloc(length+1); 
  EVP_EncodeBlock(output, plaintext, length);
  return output;

}

char* decodePassword(const unsigned char *encodedPassword, int length) {
  char *output = (char*) malloc(length+1);
  EVP_DecodeBlock(output, encodedPassword, length);
  return output;
}

				

int createSocket(char *ip, char *port) {
	int sockfd;
        struct addrinfo hints, *servinfo, *p;
        int rv;
	 memset(&hints, 0, sizeof hints);
         hints.ai_family = AF_INET6; // set to AF_INET to use IPv4
         hints.ai_socktype = SOCK_DGRAM;

	if ((rv = getaddrinfo(ip, port, &hints, &servinfo)) != 0) {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
                return 1;
        }

        // loop through all the results and make a socket
        for(p = servinfo; p != NULL; p = p->ai_next) {
                if ((sockfd = socket(p->ai_family, p->ai_socktype,
                                p->ai_protocol)) == -1) {
                        perror("talker: socket");
                        continue;
                }

                break;
        }

        if (p == NULL) {
                fprintf(stderr, "talker: failed to create socket\n");
                return 2;
        }

	return sockfd;
}

int main(int argc, char *argv[])
{
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes;
	int newfd;
	FILE *infile;
	char buf[100];
        char *IP;
        char *PORT;
	char fileInput1[100];
    	char fileInput2[100];
	char recievePort[6];
	char *emailBuffer = malloc (sizeof(char) * 1024);
	char mailMessage[100];
	char *finalPassword;
	bool quit = true;
	bool dataInput = false;
	bool auth = false;

	emailBuffer[0] = '\0';
	if (argc != 2) {
		fprintf(stderr,"usage: client filename\n");
		exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET; // set to AF_INET to use IPv4
	hints.ai_socktype = SOCK_DGRAM;

	infile = fopen(argv[1], "r");

        fscanf(infile, "%s %s", fileInput1, fileInput2);

        fclose(infile);
        strtok_r (fileInput1, "=", &IP);
        strtok_r (fileInput2, "=", &PORT);

   while(1) {
	   if(!quit) {
		break;
	   }
	if ((rv = getaddrinfo(IP, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and make a socket
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("talker: socket");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "talker: failed to create socket\n");
		return 2;
	} 

	printf("Client ready to communicate with server\n");

	while(1) {
		fgets(buf, 100, stdin);
		if ((numbytes = sendto(sockfd, buf, strlen(buf), 0, p->ai_addr, p->ai_addrlen)) == -1) {
			perror("talker: sendto");
			exit(1);
		}


		if ((numbytes = recvfrom(sockfd, buf, 100, 0,
			p->ai_addr, &p->ai_addrlen)) == -1) {
			perror("recvfrom");
			exit(1);
		}

		buf[numbytes] = '\0';
		if (strstr(buf, "200 OK") != NULL) {
			printf("Server replied with \"%s\"\n", buf);
			if ((numbytes = recvfrom(sockfd, recievePort, 100, 0, p->ai_addr, &p->ai_addrlen)) == -1) {
				perror("recvfrom");
				exit(1);
			} else {
				close(sockfd);
				if ((rv = getaddrinfo(IP, recievePort, &hints, &servinfo)) != 0) {
					fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
					return 1;
				}

		// loop through all the results and make a socket
				for(p = servinfo; p != NULL; p = p->ai_next) {
					if ((newfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
						perror("talker: socket");
						continue;
					}

					break;
				}

				if (p == NULL) {
					fprintf(stderr, "talker: failed to create socket\n");
					return 2;
				}

				break;
			}
		} 
		printf("Server replied with \"%s\"\n", buf);
	}

	while(1) {
		if (dataInput) {
			while (1) {
				memset(buf, 0, sizeof(buf));
				fgets(buf, 100, stdin);
				if(strcmp(buf, ".\n") == 0) {
					break;
				}
				strcat(emailBuffer, buf);
			}
			
			emailBuffer[strlen(emailBuffer) + 1] = '\0';
			if ((numbytes = sendto(sockfd, emailBuffer, strlen(emailBuffer), 0, p->ai_addr, p->ai_addrlen)) == -1) {
				perror("talker: sendto");
				exit(1);
			}
			printf("<- Message Sent to Server\n");
			dataInput = false;
			memset(emailBuffer, 0, sizeof(emailBuffer));		
		} else if (false) {
			fgets(buf, 100, stdin);
			if ((numbytes = sendto(sockfd, buf, strlen(buf), 0, p->ai_addr, p->ai_addrlen)) == -1) {
                                perror("talker: sendto");
                                exit(1);
                        }
			
			if ((numbytes = recvfrom(sockfd, buf, 100, 0, p->ai_addr, &p->ai_addrlen)) == -1) {
                        	perror("recvfrom");
                        	exit(1);
                	}

			fgets(buf, 100, stdin);

			char *encodedpassword = encodePassword(buf, strlen(buf));

			if ((numbytes = sendto(sockfd, encodedpassword, strlen(encodedpassword), 0, p->ai_addr, p->ai_addrlen)) == -1) {
                                perror("talker: sendto");
                                exit(1);
                        }

		} else {
			memset(buf, 0, sizeof(buf));
			fgets(buf, 100, stdin);
			if('\n' == buf[strlen(buf) - 1])
    				buf[strlen(buf) - 1] = '\0';
			if (strstr(buf, "QUIT") != NULL) {
				if(strstr(buf, "HELP") == NULL) {
					quit = false;
				}
			}

			if (auth) {
				char *encodedpassword = encodePassword(buf, strlen(buf));
				if ((numbytes = sendto(sockfd, encodedpassword, strlen(encodedpassword) + 1, 0, p->ai_addr, p->ai_addrlen)) == -1) {
                                	perror("talker: sendto");
                                	exit(1);
                        	}
				auth = false;
			} else {
				if ((numbytes = sendto(sockfd, buf, strlen(buf), 0, p->ai_addr, p->ai_addrlen)) == -1) {
                                	perror("talker: sendto");
                                	exit(1);
                        	}
			}

			printf("<- Message Sent to Server\n");
		}

		if ((numbytes = recvfrom(sockfd, buf, 100, 0,
			p->ai_addr, &p->ai_addrlen)) == -1) {
			perror("recvfrom");
			exit(1);
		}

		buf[numbytes] = '\0';
		printf("-> Server replied with \"%s\"\n", buf);

		if (strstr(buf, "354") != NULL) {
			dataInput = true;
		} else if (strstr(buf, "334 cGFzc3dvcmQ6") != NULL) {
			auth = true;
		} else if (strstr(buf, "330") != NULL) {
			strtok_r(buf, " ", &finalPassword);
			char *decodedPassword = decodePassword(finalPassword, strlen(finalPassword));
			printf("Your password: %s\n", decodedPassword);
			for (int i=0; i < 5; i++) {
				if ((numbytes = recvfrom(sockfd, buf, 100, 0, p->ai_addr, &p->ai_addrlen)) == -1) {
                        		perror("recvfrom");
                        		exit(1);
                		}
				printf("%s\n", buf);
			}
			sleep(1);
			//system("clear");
			break;
		}

		if (!quit) {
			close(sockfd);
			break;
		}

        }
   }
	freeaddrinfo(servinfo);
	return 0;
}
