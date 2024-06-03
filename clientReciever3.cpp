/* AUTHOR: Cameron Woodard
 * Description: Interface with HTTP server
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
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <ctype.h>



int main(int argc, char *argv[])
{
        int sockfd;
        struct addrinfo hints, *servinfo, *p;
        int rv;
        int numbytes;
        FILE *infile;
        char buf[100];
	char dir[100];
	DIR *folder;
        char *IP;
        char *PORT;
	char ch;
	char *finalPassword;
	bool auth = false;
	int fileCh;
	char sendMessage[100];
	char responseFile[100];
        char fileInput1[100];
        char fileInput2[100];
	char username[100];
	char confirm[100];
	char domainToUse[51];
	size_t len = 0;
	char numEmails[100];
	bool quit = false;
        struct dirent * entry;
	int fileCount = 0;

        if (argc != 2) {
                fprintf(stderr,"usage: client filename message\n");
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
while(1) {
	strcpy(sendMessage, "HELO");

	if ((numbytes = sendto(sockfd, sendMessage, strlen(sendMessage), 0,
                         p->ai_addr, p->ai_addrlen)) == -1) {
                perror("talker: sendto");
                exit(1);
        } 

	if((numbytes = recvfrom(sockfd, domainToUse, 50, 0, p->ai_addr, &p->ai_addrlen)) == -1) {

        }
       	domainToUse[numbytes] = '\0';	
	break;

}



	while(1) {
		printf("Username: ");
		scanf("%s", &username);
		printf("%s username", username); 
		sprintf(dir, "%s", username);
		folder = opendir(username);
		if (folder != NULL) {
			 printf("directory  exists\n");
		} else {
			 mkdir(dir, 0777);
			 printf("testsub Created\n");
		}
		closedir(folder);
		sprintf(sendMessage, "db/%s/1.email", username);
		printf("Number of Emails to Download: ");
		scanf("%s", &numEmails);
		sprintf(sendMessage, "GET /db%s/%s HTTP/1.1\nHOST: %s\nCount: %s", domainToUse, username, domainToUse, numEmails);
		printf("GET /db%s/%s/ HTTP/1.1\n", domainToUse, username);
		printf("Host: %s\n", domainToUse);
		printf("Count: %s\n", numEmails);
		printf("Confirm Request (Y/N)");
		scanf("%s", &confirm);
		if(strstr(confirm, "Y") !=NULL) {
			break;
		}
	}
	if ((numbytes = sendto(sockfd, sendMessage, strlen(sendMessage), 0,
                         p->ai_addr, p->ai_addrlen)) == -1) {
                perror("talker: sendto");
                exit(1);
        }

	if((numbytes = recvfrom(sockfd, buf, 200, 0, p->ai_addr, &p->ai_addrlen)) == -1) {

	}

	printf("%s\n", buf);
	if (strstr(buf, "404") != NULL) {
		printf("Terminating connection\n");
		return 1;
	}

	folder = opendir(username);
	if (folder != NULL) {
                //         printf("directory  exists\n");
                } else {
                         mkdir(dir, 0777);
                  //       printf("testsub Created\n");
                }
        while ((entry = readdir(folder)) != NULL) {
	      if (entry->d_type == DT_REG) {  //If the entry is a regular file
		      fileCount++;
	      }
        }
	closedir(folder);


	for (int i = 0; i < atoi(numEmails); i++) {
		printf("Message: %d\n", (i + 1));
		sprintf(responseFile, "%s/response%d.txt", username, fileCount);
                infile = fopen(responseFile, "a+");
		if (quit) {
			fclose(infile);
                        quit = false;
                        break;
                }
		while(1) {
			memset(buf, 0, sizeof(buf));
			if ((numbytes = recvfrom(sockfd, buf, 100, 0,
				p->ai_addr, &p->ai_addrlen)) == -1) {
				perror("recvfrom");
				exit(1);
			} else if((strstr(buf, "400") != NULL) || (strstr(buf, "404") != NULL)) {
				fclose(infile);
				printf("%s\n", buf);
				quit = true;
				break;
			} else {
				for (int i=0; i < 100; i++) {
					ch = buf[i];
					if (ch == EOF) {
						fputc((int)ch, infile);
						quit = false;
						printf("\n");
						fclose(infile);
						quit = true;
						break;
					} else {
						fputc((int)ch, infile);
						printf("%c", ch);
					}			
				}
				if (quit) {
					quit = false;
					break;
				}
			}
		}
	}
        //freeaddrinfo(servinfo);
        close(sockfd);

        return 0;
}

