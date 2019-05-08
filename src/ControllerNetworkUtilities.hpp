#ifndef ControllerNetworkUtilities_h
#define ControllerNetworkUtilities_h
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>

#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>

#include <libff/algebra/fields/field_utils.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <istream>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>

#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <sstream> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 

#include <string> 

#include <sstream> 

#include <iostream> 

#include <arpa/inet.h>
#include <iostream> 
#include <cstdint>
#include <vector>
#include "Helper.h"
#include "Block.h"

using namespace libsnark;
using namespace std;

struct response{
		int rangeStart;
		long out;
	};
struct helpersvk{
	int rangeStart;
	r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vk;
};

class ControllerNetworkUtilities {
	
	
public:
   ControllerNetworkUtilities(int initial){
      nofhelpers = initial;
    }
	ControllerNetworkUtilities(){
      nofhelpers = 0;
	  printf("Controller Message : NetUtil Constructor\r\n"); 
    }

    int getnofAvailableHelpers(){
      return nofhelpers;
    }
    vector<char*> getAvailableHelpers(){
      return IPs;
    }
	
	void send_message_to_helper(int id, const char* message, int size ){
		
		auto timebeforeminingrangesent = std::chrono::system_clock::now();
		std::time_t start_time_range = std::chrono::system_clock::to_time_t(timebeforeminingrangesent);
		std::cout << "\n ALERT !!! :Time time before mining range sent " << std::ctime(&start_time_range);    	
	
		printf("Controller Message : Send message to helper\r\n");
		if( send(socket_nums[id], message, size, 0) != size )   
            {   
                perror("send");   
            }
			
	}
	void receive_from_helper(int sizeofbuffer, char* buffer, int socket){
		
		printf( "Home message: in receive function body  message from the helper of size %d and equals %s", sizeofbuffer,buffer);
			
		
		char* tokens;
		int  _sNonce = 0, out= 0;
		
		tokens = strtok(buffer, "$");
		if (tokens!= NULL ) _sNonce = stoi(tokens);
		printf("starting nonce at:%d\n",_sNonce );
		
		tokens = strtok(NULL,"$");		
		if (tokens!= NULL ) out = stoi(tokens) ;
		printf("nonce found at :%d\n",_sNonce );
		
		if (zk==1){
			printf( "Home message: received message from the helper %s",buffer);
			if (out > 0){
				//block is found 
				cout<< "Block found";
			}
			response s; 
			s.rangeStart = _sNonce;
			s.out = (long)out;
			responses.push_back(s);
	 
		}else{
			printf( "ZK: Home message: received message from the helper %s",buffer);
			if (out> 0){
				//block is found 
				cout<< "Block found";
				auto timeafterminingrangesent = std::chrono::system_clock::now();
				std::time_t end_time_range = std::chrono::system_clock::to_time_t(timeafterminingrangesent);
	
				std::cout << "\n ALERT !!! :Time time before mining range sent " << std::ctime(&end_time_range);    	
	
			}else {
				printf( "ZK: Home message: reading proof");
				default_r1cs_ppzksnark_pp::init_public_params();
				
				r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof;
					
				tokens = strtok(NULL,"$");		
				
				if (tokens!= NULL ){
					
					char *bEOF =NULL; 
					
					printf ("\n2 ho ho hoooo");
					stringstream is;
					is.write(tokens,strlen(tokens));
					printf ("\nSize of proof = %s", tokens);
					printf ("\n3 ho ho hoooo");
					
					int valread= sizeofbuffer;
					printf ("\nSize of proof = %d",valread);
					
					while (valread>0 && bEOF==NULL)
					{
						valread = read( socket , buffer, 1024);
						if (valread > 0){
				
							bEOF = strstr(buffer, "$EOF");
								if (bEOF){
					
									printf ("##########################################buff is out");
									is.write(buffer, valread-5);
				
								}else{
			
									is.write(buffer, valread);
								}
							printf ("\nSize of proof = %d", is.str().size());
							
						}
						
					}
					printf ("from input stream to proof");
					is>>proof;
					
				}else 
				{	
					printf ("No proof is sent");
					
				}
			// verify
			//get vk 
			printf ("DONEERECEIVINGGGGGGGGGG");
			r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vk;
			for (int i=0; i< vks.size();i++){
				if (vks[i].rangeStart =_sNonce) vk = vks[i].vk;
			}
			//TODOpb.primary input in the struct
			//bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(vk, pb.primary_input(), proof);
			//cout<<"%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%the proof is "<< verified;

			}
					
						//verify the proof BIIIIG Problem we have to know what specific key was sent to whom.
			//bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), helpers[id].proof);
			//cout<<"%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%the proof is "<< verified;

			
			
			response s; 
			s.rangeStart = 0;
			s.out = (long)out;
			responses.push_back(s);
			
	
		}
		//send(socket , "BYE" , strlen("BYE") , 0 );
	}
	int zk;
	
    void updateHelpers(bool addorremove, int socket_num, char* ip, int port){
		
		 
      if(addorremove){
		  printf("Controller Message : Adding helper \r\n");
			socket_nums.emplace_back(socket_num);
			IPs.emplace_back(ip);
			ports.emplace_back(port);
			nofhelpers++;
			printf("Controller Message : number of helpers now %d\r\n",nofhelpers);
	  }else{
		   printf("Controller Message : removing helper \r\n");
		
			int pos;     
			for (int j=0; j<socket_nums.size(); j++){ if (socket_nums[j] == socket_num) pos = j;}
			socket_nums.erase(socket_nums.begin()+ pos);
			IPs.erase(IPs.begin() + pos);
			ports.erase(ports.begin()+ pos);
			nofhelpers--;
					
	  }
    }
	void con_connect ();
	
	std::vector<int> socket_nums;
	std::vector<char*> IPs;
	std::vector<int> ports;
	std::vector<response> responses;
	std::vector<helpersvk> vks;
	

  private:
    int nofhelpers;
    
};
 #endif 