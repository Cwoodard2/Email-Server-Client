/* AUTHOR: Cameron Woodard
 * Description: Program to act as both a SMTP and HTTP server
 * Features: SMTP, HTTP, Interdomain Sending, Authentification 
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
#include <time.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <ctype.h>

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//Writes server activity to log file
void writeServerLog(char logMessage[100], char *fromIP, char *toIP, char *replyCode, char *domain) {
	FILE *logFile;
	time_t t = time(NULL);
        struct tm tm = *localtime(&t);
	char date[100];
	char finalMessage[1024];
	char command[100];
	char filepath[100];
	char logDescription[100];

	if ((strstr(logMessage, "MAIL FROM:") != NULL) || (strstr(logMessage, "mail from:") != NULL)) {
		if ((strstr(logMessage, "HELP") != NULL) || (strstr(logMessage, "help") != NULL)) {
			sprintf(command, "%s", "HELP MAIL FROM:");
			strcpy(logDescription, "Client requested HELP for the MAIL FROM command");
		} else {
			sprintf(command, "%s", "MAIL FROM:");
			strcpy(logDescription, "Client issued MAIL FROM command");
		}
	} else if ((strstr(logMessage, "RCPT TO:") != NULL) || (strstr(logMessage, "rcpt to:") != NULL)) {
		if ((strstr(logMessage, "HELP") != NULL) || (strstr(logMessage, "help") != NULL)) {
			sprintf(command, "%s", "HELP RCPT TO:");
			strcpy(logDescription, "Client requested HELP for the RCPT TO command");
		} else {
			sprintf(command, "%s", "RCPT TO:");
			strcpy(logDescription, "Client issued RCPT TO command");
		}
	} else if ((strstr(logMessage, "DATA") != NULL) || (strstr(logMessage, "data") != NULL)) {
		if ((strstr(logMessage, "HELP") != NULL) || (strstr(logMessage, "help") != NULL)) {
			sprintf(command, "%s", "MAIL DATA");
			strcpy(logDescription, "Client requested HELP for the DATA command");
		} else {
			sprintf(command, "%s", "DATA");
			strcpy(logDescription, "Client issued DATA command");
		}
	} else if ((strstr(logMessage, "HELP") != NULL) || (strstr(logMessage, "help") != NULL)) {
		sprintf(command, "%s", "HELP");
		strcpy(logDescription, "Client issued the HELP command");
	}  else if ((strstr(logMessage, "QUIT") != NULL) || (strstr(logMessage, "quit") != NULL)) {
		if ((strstr(logMessage, "HELP") != NULL) || (strstr(logMessage, "help") != NULL)) {
			sprintf(command, "%s", "HELP QUIT");
			strcpy(logDescription, "Client requested HELP for the QUIT command");
		} else {
			sprintf(command, "%s", "QUIT");
			strcpy(logDescription, "Client issued the QUIT command");
		}
        } else if ((strstr(logMessage, "RSET") != NULL) || (strstr(logMessage, "rset") != NULL)) {
		if ((strstr(logMessage, "HELP") != NULL) || (strstr(logMessage, "help") != NULL)) {
                        sprintf(command, "%s", "HELP RSET");
			strcpy(logDescription, "Client requested HELP for the RSET command");
                } else {
			sprintf(command, "%s", "RSET");
			strcpy(logDescription, "Client issued the RSET command");
		}
	} else {
		sprintf(command, "%s", "N/A");
		strcpy(logDescription, logMessage);
	}

	sprintf(filepath, "db%s/server_log", domain);
	logFile = fopen(filepath, "a+");
	sprintf(date, "%d-%02d-%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
	sprintf(finalMessage, "%s %s %s %s %s %s\n", date, fromIP, toIP, command, replyCode, logMessage);
	if(fputs(finalMessage, logFile) == EOF) {
		printf("Failed to write\n");
	}
	fclose(logFile);
}

//Encodes passwords either to salt or send to client
char *encodePassword(const unsigned char *plaintext, int length) {
  char *output = (char*) malloc(length+1); 
  EVP_EncodeBlock(output, plaintext, length);
  return output;

}

//Decodes passwords in order to salt
char* decodePassword(const unsigned char *encodedPassword, int length) {
  printf("[SERVER-SMTP] Decoding Password\n");
  char *output = (char*) malloc(length+1);
  EVP_DecodeBlock(output, encodedPassword, length);
  printf("[SERVER-SMTP] Password Sucesfully Decoded\n");
  return output;
    
}

//Random password generator for unique passwords
char* generatePassword() {
	srand(time(NULL));
	FILE *fp;
	char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	char *password = malloc (sizeof(char) * 10);
	for (int i = 0; i < 5; i++) {
		int key = rand() % (int) (sizeof (charset - 1));
		password[i] = charset[key];
	}
	password[5] = '\0';
	return password;
}

//compares provided password against password in db
bool comparePassword(char *username, char *encodedPassword, char *domain) {
	printf("[SERVER-SMTP] Checking for correct password\n");
	FILE* fp;
	char password[100];
	char filepath[100];
	char salt[100] = "SNOWY22";
	char *decodedPassword = decodePassword(encodedPassword, strlen(encodedPassword));
	strcat(salt, decodedPassword);
	char *newEncodedPassword = encodePassword(salt, strlen(salt));
	sprintf(filepath, "db%s/user_pass/%s", domain, username);
	fp = fopen(filepath, "r");
	fscanf(fp, "%s", password);
	fclose(fp);
	if(!strcmp(password, newEncodedPassword)) {
		printf("[SERVER-SMTP] Password Correct\n");
		return true;
	} else {
		printf("[SERVER-SMTP] Password Incorrect\n");
		return false;
	}
	
}

//handles interdomain sending
bool interdomainSending(char *sender, char* reciever, char *messageData, char *domain, char *ip, char *port, char *ownDomain) {
	int initfd;
	int sockfd;
        struct addrinfo hints, *servinfo, *p;
        int rv;
        int numbytes;
	char buffer[100];
	char sendMessage[100];
	char portToUse[5];
	char *ownIP;
	char host[256];
	struct hostent *host_entry;
        int hostname;
        hostname = gethostname(host, sizeof(host));
        host_entry = gethostbyname(host);
        ownIP = inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0]));

	printf("[SERVER-SMTP] Beginning interdomain mailing\n");
	
	memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET; // set to AF_INET to use IPv4
        hints.ai_socktype = SOCK_DGRAM;


	if ((rv = getaddrinfo(ip, port, &hints, &servinfo)) != 0) {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
                return false;
        }

        // loop through all the results and make a socket
        for(p = servinfo; p != NULL; p = p->ai_next) {
                if ((initfd = socket(p->ai_family, p->ai_socktype,
                                p->ai_protocol)) == -1) {
                        perror("talker: socket");
                        continue;
                }

                break;
        }

        if (p == NULL) {
                fprintf(stderr, "talker: failed to create socket\n");
                return false;
        }
	
	printf("[SERVER-SMTP] Saying HELO to remote server\n");
	sprintf(sendMessage, "HELO %s", domain);
	writeServerLog(sendMessage, ownIP, ip, "N/A", ownDomain);
	if ((numbytes = sendto(initfd, sendMessage, strlen(sendMessage), 0, p->ai_addr, p->ai_addrlen)) == -1) {
		perror("talker: sendto");
		exit(1);
	}

	if ((numbytes = recvfrom(initfd, buffer, 100, 0, p->ai_addr, &p->ai_addrlen)) == -1) {
		perror("recvfrom");
		exit(1);
	}
	writeServerLog(buffer, ip, ownIP, "N/A", ownDomain);


	if ((numbytes = recvfrom(initfd, portToUse, 100, 0, p->ai_addr, &p->ai_addrlen)) == -1) {
                perror("recvfrom");
                exit(1);
        }
	writeServerLog(buffer, ip, ownIP, "N/A", ownDomain);

	if ((numbytes = recvfrom(initfd, buffer, 100, 0, p->ai_addr, &p->ai_addrlen)) == -1) {
                perror("recvfrom");
                exit(1);
        }
	writeServerLog(buffer, ip, ownIP, "N/A", ownDomain);

	close(initfd);

	if ((rv = getaddrinfo(ip, portToUse, &hints, &servinfo)) != 0) {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
                return false;
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
                return false;
        }

	sleep(1);

	for (int i = 0; i < 6; i++) {
		switch(i) {
			case 0:
				sprintf(sendMessage, "%s", "AUTH rasta#22smtp");
				break;
			case 1:
				sprintf(sendMessage, "%s", sender);
				break;
			case 2:
				sprintf(sendMessage, "%s", reciever);
				break;
			case 3:
				sprintf(sendMessage, "%s", "DATA");
				break;
			case 4:
				break;
			case 5: 
				printf("[SERVER-SMTP] Sent Interdomain Mail Successfully\n");
        			printf("[SERVER-SMTP] Closing connection with other server\n");
				sprintf(sendMessage, "%s", "QUIT");
				break;
		}
		if (i != 4) {
			writeServerLog(sendMessage, ownIP, ip, "N/A", ownDomain);
			if ((numbytes = sendto(sockfd, sendMessage, strlen(sendMessage), 0, p->ai_addr, p->ai_addrlen)) == -1) {
				perror("talker: sendto");
				exit(1);
			}
		} else {
			sprintf(sendMessage, "%s", "Transmitting Message Data");
			writeServerLog(sendMessage, ownIP, ip, "N/A", ownDomain);
			if ((numbytes = sendto(sockfd, messageData, strlen(messageData), 0, p->ai_addr, p->ai_addrlen)) == -1) {
                                perror("talker: sendto");
                                exit(1);
                        }
		}

		if ((numbytes = recvfrom(sockfd, buffer, 100, 0, p->ai_addr, &p->ai_addrlen)) == -1) {
                	perror("recvfrom");
                	exit(1);
        	}
		writeServerLog(buffer, ip, ownIP, "N/A", ownDomain);

		if(strstr(buffer, "Error") != NULL) {
			sprintf(sendMessage, "%s", "CLOSE CONNECTION");
			writeServerLog(sendMessage, ownIP, ip, "N/A", ownDomain);
			if ((numbytes = sendto(sockfd, sendMessage, strlen(sendMessage), 0, p->ai_addr, p->ai_addrlen)) == -1) {
                                perror("talker: sendto");
                                exit(1);
                        }
			close(sockfd);
			return false;
		}
	}
	close(sockfd);	
	return true;
}

//runs the HTTP server
void httpServer(int fd, char *ownDomain) {
	struct sockaddr_storage their_addr;
	socklen_t addr_len;
	int numbytes;
	char buf[300];
	bool failState = true;
	char ch;
	char s[100];
	char *command;
	char filePath[100];
	char getBuffer[100];
	char httpType[100];
	char host[100];
	char domain[100];
	char countTitle[100];
	char count[100];
	char fileToOpen[100];
	char fileTest[100];
	char errorMessage[100];
	char logMessage[1024];
	char replyCode[10];
	char *IP;
	FILE *fp;
	FILE *logFile;
	DIR *dir;
	char date[100];
	struct dirent * entry;
	time_t t = time(NULL);
        struct tm tm = *localtime(&t);
	addr_len = sizeof their_addr;
	struct hostent *host_entry;
        int hostname;
        hostname = gethostname(host, sizeof(host));
        host_entry = gethostbyname(host);
        IP = inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0]));


	printf("[SERVER-HTTP] HTTP server running\n");
	while(1) {

		if ((numbytes = recvfrom(fd, buf, 100, 0, (struct sockaddr *)&their_addr, &addr_len)) == -1) {
                        perror("recvfrom");
                        exit(1);
                }


		if ((numbytes = sendto(fd, ownDomain, strlen(ownDomain), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
                                perror("talker: sendto");
                                exit(1);
                }

		failState = true;
		memset(buf, 0, sizeof(buf));
		if ((numbytes = recvfrom(fd, buf, 100, 0, (struct sockaddr *)&their_addr, &addr_len)) == -1) {
			perror("recvfrom");
			exit(1);
		} else {
			 printf("%s\n", buf);
		}
		inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
		writeServerLog(buf, s, IP, "N/A", ownDomain);
		strtok_r(buf, "/", &command);
		if (strstr(buf, "GET") != NULL) {
			sscanf(command, "%s %s %s %s %s %s", filePath, httpType, host, domain, countTitle, count);
			dir = opendir(filePath);
			if(dir == NULL) {
				printf("[SERVER-HTTP] File not found (code 404)\n");
                        	sprintf(buf, "Error 404: File Not Found: No emails for the user were found.");
                        	failState = false;
		       		closedir(dir);
                	} else {
				printf("[SERVER-HTTP] Found requested user\n");
				closedir(dir);
                	}
		} else {
			printf("[SERVER-HTTP] Recieved bad GET request (code 400)\n");
			failState = false;
			sprintf(buf, "Error 400: Bad Request");
		}
	
		if (!failState) {
			writeServerLog(buf, s, IP, "N/A", ownDomain);
			if ((numbytes = sendto(fd, buf, strlen(buf), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
                                perror("talker: sendto");
                                exit(1);
                        }
			continue;
		} else {
			sprintf(date, "Date: %d-%02d-%02d %02d:%02d:%02d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
			sprintf(buf, "HTTP/1.1 200 OK\nServer: %s\n Last-Modified: %s\nCount: %s\nContent-Type: text/plain\n", domain, date, count);
			writeServerLog(buf, IP, s, "200", ownDomain);
			if ((numbytes = sendto(fd, buf, strlen(buf), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {

			}
		}

		dir = opendir(filePath);

		//Reads the ../ and ./ so that the number of emails counted is not affected
		for (int i = 0; i < 2; i++) {
			if ((entry = readdir(dir)) != NULL) {
                        }

		}

		for (int i = 1; i < (atoi(count) + 1); i++) {
			failState = true;
			if ((entry = readdir(dir)) != NULL) {
			      if (entry->d_type == DT_REG) {  //If the entry is a regular file
					printf("[Server-HTTP] Sending %s\n", entry->d_name);
			      }
		        } else {
				printf("[Server-HTTP] Requested email not found\n");
				sprintf(errorMessage, "Error 404: File Not Found: Requested emails are greater than amount of unread emails.");
				failState = false;
				printf("<- [Server-HTTP] Giving Error 404 to Reciever\n");
				writeServerLog(buf, IP, s, "N/A", ownDomain);
				if ((numbytes = sendto(fd, errorMessage, strlen(errorMessage), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
					perror("talker: sendto");
					exit(1);
				}
				closedir(dir);
				break;
		        }
			sprintf(fileToOpen, "%s/%s", filePath, entry->d_name);
			
			if((fp = fopen(fileToOpen, "r")) == NULL) {
                        	printf("[SERVER-HTTP] Requested email not found\n");
                        	sprintf(errorMessage, "Error 404: File Not Found");
                        	failState = false;
				writeServerLog(buf, IP, s, "N/A", ownDomain);
				if ((numbytes = sendto(fd, errorMessage, strlen(errorMessage), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
                                        perror("talker: sendto");
                                        exit(1);
                                }
				break;
                	} else {
                        	printf("[SERVER-HTTP] File Found\n");
                	} 
			
			printf("[Server-HTTP] Requested email able to be sent\n");

			while(1) {

				if(!failState) {
					break;
				}
				for (int i=0; i < 100; i++) {
					ch = fgetc(fp);
					buf[i] = ch;
					if (ch == EOF) {
						failState = false;
						fclose(fp);
						remove(fileToOpen);
						break;
					}	
				}

				writeServerLog(buf, IP, s, "N/A", ownDomain);
				if ((numbytes = sendto(fd, buf, strlen(buf), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
					perror("talker: sendto");
					exit(1);
				}
			}
		}
	}
	return;
}

//creates sockets for the server
int createSocket(char *port) {
	int sockfd;
        struct addrinfo hints, *servinfo, *p;
        int rv;
        struct sockaddr_storage their_addr;
        char buf[100];
        socklen_t addr_len;
        char s[INET6_ADDRSTRLEN];

	memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET; // set to AF_INET to use IPv4
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE; // use my IP


        if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
                return 1;
        }

        // loop through all the results and bind to the first we can
        for(p = servinfo; p != NULL; p = p->ai_next) {
                if ((sockfd = socket(p->ai_family, p->ai_socktype,
                                p->ai_protocol)) == -1) {
                        perror("listener: socket");
                        continue;
                }

                if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
                        close(sockfd);
                        perror("listener: bind");
                        continue;
                }

                break;
        }

        if (p == NULL) {
                fprintf(stderr, "listener: failed to bind socket\n");
                return 2;
        }

        freeaddrinfo(servinfo);
	return sockfd;
}

//Configures SMTP and HTTP servers, and begins running them
int main(int argc, char *argv[]) {
	int smtpfd;
	int httpfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes;
	struct sockaddr_storage their_addr;
	char buf[100];
	socklen_t addr_len;
	char s[100];
	char dataMessage[1025];
	FILE *infile;
	int smtpPort = 0;
	int httpPort = 0;
	char filepath[100];
	char *SMTP;
	char *HTTP;
	char fileInput1[100];
    	char fileInput2[100];
	char sendMessage[100];
	char command[100];
	char space[10];
	char sender[100];
	char reciever[100];
	char *dataToSend;
	char date[100];
	char from[100];
	char to[100];
	char dir[100];
	char sendPort[100];
	char replyCode[10];
	char password[100];
	char *user;
	bool helo;
	bool mail;
	bool rcpt;
	bool data;
	bool interDomainMailSender = false;
	bool interDomainMailReciever = false;
	bool auth = false;
	bool quit = true;
	int file_count = 0;
	int numDomains = 0;
	DIR *folder;
	struct dirent * entry;
	FILE *fp;
	time_t t = time(NULL);
        struct tm tm = *localtime(&t);
	char host[256];
   	char *IP;
	char alteredBuf[100];
	char blankSpace[100];
	char *domainBuffer[100];
	char domain[100];
	char remoteDomain[100];
	char *remoteIP;
	char *remotePort;
	char remoteDomains[10][15];
        char remoteIPs[10][25];
        char remotePorts[10][20];
	char username[100];
	char recipient[100];
	char domainCheck[100];
	char messageDescription[100];
   	struct hostent *host_entry;
   	int hostname;
	hostname = gethostname(host, sizeof(host));
	host_entry = gethostbyname(host);
	IP = inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0]));


	if (argc != 2) {
        	fprintf(stderr,"usage: client filename\n");
        	exit(1);
    	}

	infile = fopen(argv[1], "r");
	
	printf("[SERVER-SMTP] Configuring Server\n");
    	fscanf(infile, "%s %s %s", domain, fileInput1, fileInput2);

	if (strstr(domain, ".edu") == NULL) {
		sprintf(domainCheck, "@%s.edu", domain);
	} else {
		sprintf(domainCheck, "@%s", domain);
	}
	printf("[SERVER-SMTP] Checking for known remote domains\n");
	while(1) {
                if(numDomains == 10) {
                        break;
                }
                if(fscanf(infile, "%s %s %s", remoteDomains[numDomains], remoteIPs[numDomains], remotePorts[numDomains]) != 3) {
                        break;
                }
		numDomains++;
        }
    	fclose(infile);

    	printf("%s %s %s\n", domain, fileInput1, fileInput2);
    	strtok_r (fileInput1, "=", &SMTP);
    	strtok_r (fileInput2, "=", &HTTP);
	smtpPort = atoi(SMTP);
	smtpfd = createSocket(SMTP);
        httpfd = createSocket(HTTP);

	sprintf(filepath, "db%s", domain);
	folder = opendir(filepath);
	if (folder != NULL) {
		printf("[Server-Internal] db folder exists\n");
	} else {
		mkdir(filepath, 0777);
		sprintf(filepath, "db%s/user_pass", domain);
		mkdir(filepath, 0777);
		printf("[Server-Internal] db Created\n");
	}

	if(!fork()) {
                httpServer(httpfd, domain);
		close(httpfd);
        }



	while(1) {

		printf("[Server-SMTP] Waiting for messages\n");

		addr_len = sizeof their_addr;
		
		while(1) {
			if ((numbytes = recvfrom(smtpfd, buf, 100, 0, (struct sockaddr *)&their_addr, &addr_len)) == -1) {
				perror("recvfrom");
				exit(1);
			}
			inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
			writeServerLog(buf, s, IP, "N/A", domain);

		     if (strstr(buf, "HELO") != NULL || strstr(buf, "helo") != NULL){
			     if(strstr(buf, domain) == NULL) {
				printf("[Server-SMTP] Invalid HELO detected\n");
				sprintf(sendMessage, "%s", "Error: Missing Domain Name");
				writeServerLog(sendMessage, IP, s, "N/A", domain);
				if ((numbytes = sendto(smtpfd, sendMessage, strlen(sendMessage), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
                                	perror("talker: sendto");
                                	exit(1);
                        	}
                         	continue;
			     }
			     printf("<- [Server-SMTP] Valid HELO recieved. Sending 200 OK and communication port\n");
			    smtpPort++;
			    if (smtpPort == atoi(HTTP)) {
				smtpPort++;
			    }
			sprintf(sendMessage, "%s", "200 OK: Please type AUTH next.");
			writeServerLog(sendMessage, IP, s, "200", domain);
			if ((numbytes = sendto(smtpfd, sendMessage, strlen(sendMessage), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
				perror("talker: sendto");
				exit(1);
			}
			sprintf(sendPort, "%d", smtpPort);
			writeServerLog(sendMessage, IP, s, "N/A", domain);
			if ((numbytes = sendto(smtpfd, sendPort, strlen(sendPort), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
                                perror("talker: sendto");
                                exit(1);
                        }
			break;
		     } else {
			     printf("[Server-SMTP] Invalid sequence of commands\n");
			     sprintf(sendMessage, "Error 503: Incorrect Sequence of Commands. Expecting HELO <domain>");
			     writeServerLog(sendMessage, IP, s, "503", domain);
			 if ((numbytes = sendto(smtpfd, sendMessage, strlen(sendMessage), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
				perror("talker: sendto");
				exit(1);
			}
			 continue;
		     }
		}

		if(!fork()) {
			FILE *authFile;
			int forkfd;
			bool userSet;
			bool passSet;
			bool validPass = false;
			helo = true;
			sprintf(sendMessage, "%d", smtpPort);
			memset(buf, 0, sizeof(buf));
			writeServerLog(sendMessage, IP, s, "N/A", domain);
			if ((numbytes = sendto(smtpfd, sendMessage, strlen(sendMessage), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
				perror("talker: sendto");
				exit(1);
			}
			close(smtpfd);
			forkfd = createSocket(sendMessage);
			printf("[SERVER-SMTP] Forked Socket Created\n");

			while(1) {
				inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
				memset(buf, 0, sizeof(buf));	
				printf("[SERVER-SMTP] Waiting for Message on forked socket\n");
				if ((numbytes = recvfrom(forkfd, buf, 100, 0,(struct sockaddr *)&their_addr, &addr_len)) == -1) {
					perror("recvfrom");
					exit(1);
				}
				writeServerLog(buf, s, IP, "N/A", domain);
					
				printf("[Server-SMTP] Recieved packet from  %s\n", s);
				
				
				if (!auth == 1) {
					if(strstr(buf, "AUTH") != NULL) {
						if(strstr(buf, "rasta#22smtp") != NULL) {
                                                        strcpy(sendMessage, "334");
							auth = true;
							interDomainMailReciever = true;
							strcpy(replyCode, "334");
							writeServerLog(sendMessage, IP, s, replyCode, domain);
                                                        if ((numbytes = sendto(forkfd, sendMessage, strlen(sendMessage), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
                                                                perror("talker: sendto");
                                                                exit(1);
                                                        }
                                                        continue;
                                                 }
						strcpy(sendMessage, "334 dXNlcm5hbWU6");
						writeServerLog(sendMessage, IP, s, "334", domain);
						if ((numbytes = sendto(forkfd, sendMessage, strlen(sendMessage), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
                                        		perror("talker: sendto");
                                        		exit(1);
                                		}

						if ((numbytes = recvfrom(forkfd, username, 100, 0,(struct sockaddr *)&their_addr, &addr_len)) == -1) {
                                        		perror("recvfrom");
                                        		exit(1);
                                		}

						writeServerLog(username, s, IP, "N/A", domain);


						sprintf(filepath, "db%s/user_pass/%s", domain, username);
						if (access(filepath, F_OK) == -1) {
							printf("[SERVER-SMTP] Username not found. Creating account\n");
							char passwordToEncode[100] = "SNOWY22";
							char *generatedPassword = generatePassword();
							strcat(passwordToEncode, generatedPassword);
							char *passwordToSend = encodePassword(generatedPassword, strlen(generatedPassword));
							char *passwordToFile = encodePassword(passwordToEncode, strlen(passwordToEncode));
							authFile = fopen(filepath, "w");
							if (authFile == NULL) {
								perror("Error");
							}
							fputs(passwordToFile, authFile);
							sprintf(sendMessage, "330: %s", passwordToSend);
							writeServerLog(sendMessage, IP, s, "N/A", domain);
							if ((numbytes = sendto(forkfd, sendMessage, strlen(sendMessage), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
                                                       		perror("talker: sendto");
                                                        	exit(1);
                                                	}
							fclose(authFile);

							for (int i = 5; i >= 0; i--) {
								sprintf(sendMessage, "You have %d seconds.", i);
								writeServerLog(buf, IP, s, "N/A", domain);
								if ((numbytes = sendto(forkfd, sendMessage, strlen(sendMessage), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
                                                                	perror("talker: sendto");
                                                                	exit(1);
                                                        	}
								sleep(1);
							}
							close(forkfd);
							break;
						} 

						strcpy(sendMessage, "334 cGFzc3dvcmQ6");

						writeServerLog(sendMessage, IP, s, "N/A", domain);
						if ((numbytes = sendto(forkfd, sendMessage, strlen(sendMessage), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
                                                        perror("talker: sendto");
                                                        exit(1);
                                                }

                                                if ((numbytes = recvfrom(forkfd, password, 100, 0,(struct sockaddr *)&their_addr, &addr_len)) == -1) {
                                                        perror("recvfrom");
                                                        exit(1);
                                                }
						writeServerLog(password, s, IP, "N/A", domain);

						printf("[SERVER-SMTP] Preparing to compare password\n");
						
						
						validPass = comparePassword(username, password, domain);
						if(validPass) {
							printf("[SERVER-SMTP] Password Accepted (code 235)\n");
							strcpy(sendMessage, "235: Authentication Succeeded: Follow prompt or use other command\nMAIL FROM:");
							auth = true;
						} else {
							printf("[SERVER-SMTP] Password not Accepted (code 535)\n");
							strcpy(sendMessage, "535: Authentication Credentials Invalid");
						}
						

						writeServerLog(sendMessage, IP, s, "N/A", domain);
						if ((numbytes = sendto(forkfd, sendMessage, strlen(sendMessage), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
                                                        perror("talker: sendto");
                                                        exit(1);
                                                }
						
						continue;
					} else {
						strcpy(sendMessage, "Error 503: Incorrect Sequence of Commands; AUTH must come first");
					}
				}

			if (auth == 1) {
				if (!rcpt) {
                                        sprintf(alteredBuf, "MAIL FROM: %s", buf);
                                }
				if (strstr(buf, "HELP") != NULL || strstr(buf, "help") != NULL) {
					printf("[Server-SMTP] Sending HELP to Reciever (code 211)\n");
					strcpy(replyCode, "211");
					if (strstr(buf, "MAIL") != NULL) {
                                                strcpy(sendMessage, "211 OK: MAIL FROM: <user>\n This command asks for a sender in the form name@<domain>.");
                                        } else if (strstr(buf, "RCPT") != NULL) {
                                                strcpy(sendMessage, "211 OK: RCPT TO: <user>\n This command asks for a recipient in the form name@<domain>");
                                        } else if (strstr(buf, "DATA") != NULL) {
                                                strcpy(sendMessage, "211 OK: DATA\n This command starts a prompt for the user to enter the mail message.");
                                        } else if (strstr(buf, "RSET") != NULL) {
                                                strcpy(sendMessage, "211 OK: RSET\n This command resets all current buffers and resets a mail interaction.");
                                        } else if (strstr(buf, "QUIT") != NULL) {
                                                strcpy(sendMessage, "211 OK: QUIT\n This command ends the current session with the server.");
                                        } else {
                                                strcpy(sendMessage, "211 OK: HELP\n Available commands:\n MAIL FROM \n RCPT TO \n DATA \n RSET \n QUIT \n");
                                        }		
				} else if (strstr(buf, "QUIT")!= NULL || strstr(buf, "quit") != NULL) {
					strcpy(replyCode, "221");
					printf("[Server-SMTP] Quit Recieved: Ending interaction (code 221)\n");
					strcpy(sendMessage, "221 OK: Ending Mail interaction");
					quit = false;
				} else if (strstr(buf, "RSET") != NULL || strstr(buf, "rset") != NULL) {
					strcpy(replyCode, "250");
					rcpt = false;
					data = false;
					strcpy(sender, "");
					strcpy(reciever, "");
					strcpy(dir, "");
					strcpy(filepath, "");
					interDomainMailReciever = false;
					interDomainMailSender = false;
					strcpy(sendMessage, "250 OK: Reset Requested, Mail interaction canceled: Follow Prompt or use another command\nMAIL FROM:");
					printf("[Server-SMTP] Reset Requested, Mail interaction canceled (code 250)\n");
				} else if (strstr(alteredBuf, "MAIL FROM:") != NULL && !rcpt) {
                                        if (((strstr(alteredBuf, domainCheck) != NULL) && (strstr(alteredBuf, username) != NULL)) || interDomainMailReciever) {
						strcpy(replyCode, "250");
                                                sscanf(alteredBuf, "%s %s %s", command, space, sender);
						if (strstr(sender, ".edu") != NULL) {
                                                	rcpt = true;
                                                	strcpy(sendMessage, "250, Sender OK: Follow Prompt or use another command\nRCPT TO:");
							printf("[Server-SMTP] Sender OK (code 250)\n");
						} else {
							strcpy(sendMessage, "Error: 250, Incorrect parameters: Only type your email, not the command");
                                                        printf("[Server-SMTP] Incorrect Parameters (code 500)\n");
						}
                                        } else {
						strcpy(replyCode, "550");
						printf("[Server-SMTP] No sender here (code 550)\n");
                                                strcpy(sendMessage, "Error 550: Sender not recognized\nMAIL FROM: ");
                                        }
                                } else if (rcpt && !data) {
					sprintf(alteredBuf, "RCPT TO: %s", buf);
					if (strstr(alteredBuf, "RCPT TO:") != NULL || strstr(alteredBuf, "rcpt to:") != NULL) {
						memset(fileInput1, 0, sizeof(fileInput1));
						memset(fileInput2, 0, sizeof(fileInput2));
						for (int i = 0; i < numDomains; i++) {
							if (strstr(alteredBuf, remoteDomains[i]) != NULL) {
								printf("[SERVER-SMTP] Remote Domain Email Found. Switching to Interdomain Mail Mode\n");
								interDomainMailSender = true;
								strcpy(remoteDomain, remoteDomains[i]);
								strcpy(fileInput1, remoteIPs[i]);
								strcpy(fileInput2, remotePorts[i]);
								strtok_r(fileInput1, "=", &remoteIP);
								strtok_r(fileInput2, "=", &remotePort);
							}
						}
						if ((strstr(alteredBuf, domainCheck) != NULL) || interDomainMailSender) {
							strcpy(replyCode, "250");
							sscanf(alteredBuf, "%s %s %s", command, space, reciever);
							memcpy(recipient, reciever, strlen(reciever));
							if (strstr(reciever, ".edu") != NULL) {
								strtok_r (recipient, "@", &user);
								sprintf(dir, "db%s/%s", domain, recipient);
								folder = opendir(dir);
								if (folder != NULL) {
									printf("[SERVER-SMTP] User Directory Exists\n");
								} else {
									mkdir(dir, 0777);
									printf("[SERVER-SMTP] New User Directory Created\n");
								}
								closedir(folder);
								rcpt = true;
								data = true;
								strcpy(sendMessage, "250, Reciever OK: Please type DATA or use another command");
								printf("[Server-SMTP] Reciever OK (code 250)\n");
							} else {
								strcpy(sendMessage, "Error: 250, Incorrect parameters: Only type reciever's email");
								printf("[Server-SMTP] Incorrect Parameters (code 500)\n");
							}
						} else {
							strcpy(replyCode, "550");
							printf("[Server-SMTP] No reciever here (code 550)\n");
							strcpy(sendMessage, "Error 550: Reciever Not Recognized");
						}
					} else {
						if (strstr(buf, "MAIL FROM:") != NULL) {
							strcpy(replyCode, "503");
							strcpy(sendMessage, "Error 503: Bad Sequence of commands");
							printf("[SERVER-SMTP] Incorrect Sequence of commands detected (code 503)\n");
						} else if (strstr(buf, "DATA") != NULL) {
							strcpy(replyCode, "503");
							strcpy(sendMessage, "Error 503: Bad Sequence of commands");
							printf("[SERVER-SMTP] Incorrect Sequence of commands detected (code 503)\n");
						} else {
							strcpy(replyCode, "500");
							strcpy(sendMessage, "Error 500: Command Unrecognized. Type HELP for commands.");
							printf("[SERVER-SMTP] Incorrect Sequence of commands detected (code 503)\n");
						}
					}
				} else if (data) {
					if (strstr(buf, "DATA") != NULL) {
						printf("[Server-SMTP] Gathering DATA\n");
						strcpy(sendMessage, "354: Enter a message to send; End with <CRLF>.<CRLF>");
						writeServerLog(sendMessage, IP, s, "354", domain);
						if ((numbytes = sendto(forkfd, sendMessage, strlen(sendMessage), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
							perror("talker: sendto");
							exit(1);
						}

						if ((numbytes = recvfrom(forkfd, dataMessage, 100, 0,(struct sockaddr *)&their_addr, &addr_len)) == -1) {
							perror("recvfrom");
							exit(1);
						}

						dataMessage[numbytes] = '\0';
						writeServerLog(buf, s, IP, "N/A", domain);

						rcpt = false;
						data = false;

						if (interDomainMailSender) {
							interDomainMailSender = false;
							printf("[SERVER-SMTP] Reciever domain different from server domain.\n");

							if(interdomainSending(sender, reciever, dataMessage, remoteDomain, remoteIP, remotePort, domain)) {
								strcpy(sendMessage, "250, Data Recieved and ready for delivery! Follow Prompt or use another command\nMAIL FROM: ");
								strcpy(replyCode, "250");
							} else {
								strcpy(replyCode, "250");
								strcpy(sendMessage, "504, Data failed to be delivered: Follow Prompt or use another command\nMAIL FROM: ");
							}

							writeServerLog(sendMessage, IP, s, "354", domain);
							if ((numbytes = sendto(forkfd, sendMessage, strlen(sendMessage), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
                                        			perror("talker: sendto");
                                        			exit(1);
                                			}
						       continue;	
						}

						file_count++;
						folder = opendir(dir);
			                     	 while ((entry = readdir(folder)) != NULL) {
						      if (entry->d_type == DT_REG) {  //If the entry is a regular file
                                                              file_count++;
                                                      }
			                      	}
						closedir(folder);
						sprintf(filepath, "%s/%d.email", dir, file_count);
						fp = fopen(filepath, "a");
						sprintf(date, "Date: %d-%02d-%02d %02d:%02d:%02d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
						sprintf(from, "FROM: %s\n", sender);
						sprintf(to, "To: %s\n", reciever);
						fputs(date, fp);
						fputs(from, fp);
						fputs(to, fp);
						fputs("\n\n", fp);
						fputs(dataMessage, fp);
						fclose(fp);  
						strcpy(replyCode, "250");
						strcpy(sendMessage, "250, Data Recieved and ready for delivery! Follow Prompt or use another command\nMAIL FROM: ");
						printf("[SERVER-SMTP] Data has been recieved and delivered. Ready for another mail interaction (code 250)\n");
					} else {
						if (strstr(buf, "MAIL") != NULL) {
							strcpy(replyCode, "503");
                                                        strcpy(sendMessage, "Error 503: Bad Sequence of commands: Please type DATA");
							printf("[SERVER-SMTP] Incorrect Sequence of commands detected (code 503)\n");
                                                } else if (strstr(buf, "RCPT") != NULL) {
							strcpy(replyCode, "503");
                                                        strcpy(sendMessage, "Error 503: Bad Sequence of commands Please type DATA");
							printf("[SERVER-SMTP] Incorrect Sequence of commands detected (code 503)\n");
                                                } else {
							strcpy(replyCode, "500");
                                                        strcpy(sendMessage, "Error 500: Command Unrecognized. Type HELP for commands or type DATA");
							printf("[SERVER-SMTP] Incorrect Sequence of commands detected (code 503)\n");
                                                }
					}
				} else {
					strcpy(replyCode, "500");
					strcpy(sendMessage, "Error 500: Command Unrecognized. Type HELP for commands. Please follow prompt");
					printf("[SERVER-SMTP] Detected Unrecognized Command (code 500)\n");
				}
			}

				writeServerLog(sendMessage, IP, s, replyCode, domain);
		
				if ((numbytes = sendto(forkfd, sendMessage, strlen(sendMessage), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
					perror("talker: sendto");
					exit(1);
				}

				if (!quit) {
					printf("[SERVER-SMTP] Closing Forked Socket\n");
					close(forkfd);
					break;
				}
				}
			}
		}

	close(smtpfd);

	return 0;
}

