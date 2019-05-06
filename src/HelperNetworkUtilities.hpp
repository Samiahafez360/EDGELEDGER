// Client side C/C++ program to demonstrate Socket programming 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 

#include <string> 

#include <sstream> 

#include <iostream> 

#include <arpa/inet.h>
#include "Helper.h"

#define PORT 8888 
using namespace libsnark;
using namespace std;


class HelperNetworkUtilities {
public:
int zk;
int hel_connect() 
{ 
	struct sockaddr_in address; 
	int sock = 0, valread; 
	struct sockaddr_in serv_addr; 
	char *hello = "-1"; 
	 
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{ 
		printf("\n Socket creation error \n"); 
		return -1; 
	} 

	memset(&serv_addr, '0', sizeof(serv_addr)); 

	serv_addr.sin_family = AF_INET; 
	serv_addr.sin_port = htons(PORT); 
	
	// Convert IPv4 and IPv6 addresses from text to binary form 
	if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) 
	{ 
		printf("\nInvalid address/ Address not supported \n"); 
		return -1; 
	} 

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
	{ 
		printf("\nConnection Failed \n"); 
		return -1; 
	} 
	printf("Buffer at the helper reaaaad"  ); 
	char buffer[10240] = {0};
	string strchararr= submine(buffer, sock);
	
	const char * outchararr =strchararr.c_str();
	//out.copy(outchararr, out.size()+1);
	//outchararr[out.size()] ='\0';
	
	//send(sock , outchararr , strlen(outchararr) , 0 );
	if (send(sock , outchararr , strchararr.size() , 0 )!= strchararr.size() ){
		perror("send"); 
	}
	printf("\n nonce sent %s\n size of message %d ",outchararr,strchararr.size()); 
	
	
	//valread = read( sock , buffer, 1024);
	return 0; 
} 
	
	//totally wrong but will do it for now 
	string submine(char* input, int sock){
		
		int valread = read( sock , input, 1024);
		printf("Buffer at the %d helper:%s\n",valread, input  ); 
		
		
		char* tokens;
		tokens = strtok(input, "$");
		
		//uint32_t _sNonce, uint32_t range,uint32_t nDifficulty,Block mBlock,std::chrono::system_clock::time_point starttime);
		int  _sNonce = 0, range= 0, nDifficulty= 0;
		char * blocknoonce;
		long long starttime;
		if (tokens!= NULL ) _sNonce = stoi(tokens);
		
		tokens = strtok(NULL,"$");
		printf("starting nonce at:%d\n",_sNonce );
		if (tokens!= NULL ) range = stoi(tokens) ;
		
		tokens = strtok(NULL,"$");
		printf("range:%d\n",range);
		if (tokens!= NULL ) nDifficulty = stoi(tokens) ;
		printf("difficulty:%d\n",nDifficulty);
		
		tokens = strtok(NULL,"$");
		if (tokens!= NULL ){
			blocknoonce = new char[strlen(tokens) + 1]; 
			strcpy(blocknoonce, tokens);
			blocknoonce[strlen(tokens)]='\0';
		}
		
		printf("block without nonce:%s\n",blocknoonce);
		
		tokens = strtok(NULL,"$");
		
		if (tokens!= NULL ) starttime = stoll(tokens);
		
		
		int out = -1;
		Helper* h = new Helper();
		if (zk == 1)
			
		{
			out = h->minenozk_net(_sNonce*range,range ,nDifficulty,blocknoonce, starttime);
			printf("difficulty:%d\n",out);
		}
		else
		{
			tokens = strtok(NULL,"$");
			printf ("1 zk at helper \n");
			default_r1cs_ppzksnark_pp::init_public_params();
			r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> pk;
			if (tokens!= NULL ){

				char *bEOF =NULL; 
				stringstream is;
				is << tokens;
				do
				{
					valread = read( sock , input, 10240);
					if (valread > 0){
						
						bEOF = strstr(input, "$EOF");
						if (bEOF){
							
							printf ("##########################################buff is out");
							is.write(input, valread-5);
						
						}else{
					
							is.write(input, valread);
						}
						printf ("\nSize of pk = %d", is.str().size());
					}
					
				}while (valread>0 && bEOF==NULL);

				printf ("2 zk at helper \n Size of pk = %d", is.str().size());
				
				is >> pk;
				
				printf("block without nonce:%s\n",blocknoonce);
				
				out = h->minezk(_sNonce*range,range,nDifficulty,blocknoonce, pk,starttime);
			
			}else{
				printf ("no proof sent are you sure we are mining with zkp? \n");
			}
		}
		
		stringstream ss;
		ss<<_sNonce<<"$"<<out;
		if (zk >= 2){
			ss<<"$"<<h->proof<<"$EOF\0";
		}
		const string tmp =ss.str();
		return tmp;
	}
};
