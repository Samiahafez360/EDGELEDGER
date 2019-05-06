#ifndef HELPER_H
#define HELPER_H

#include <cstdint>
#include <vector>
#include <iostream>

#include <iterator> 
#include <map> 
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libff/algebra/fields/field_utils.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <istream>
#include <Block.h>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <PoW_bulk_hash_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <string>
#include <chrono>
using namespace libsnark;
class Helper {
	
public:
	
	Helper();
	Helper(int sizofgad);
    int minezk_bulk(int srange,uint32_t start, uint32_t range,uint32_t nDifficulty,long long starttime,char* mBlock);

	int minenozk(uint32_t _sNonce, uint32_t range,uint32_t nDifficulty,Block mBlock,std::chrono::system_clock::time_point starttime);
	int minenozk_net(uint32_t _sNonce, uint32_t range,uint32_t nDifficulty,char* mBlock,long long starttime);

	

	int minezk(uint32_t start, uint32_t range,uint32_t nDifficulty,char* mBlock,r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> pk,long long starttime);
	//int minezk(uint32_t start, uint32_t range,uint32_t nDifficulty,Block mBlock,r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> pk, std::chrono::system_clock::time_point starttime);

	r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof;
    char* getIP();
	
	typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;
	typedef sha256_two_to_one_hash_gadget<FieldT> HashT;
	map<int,r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp>> proofs;
	
private:
	// for either gadgets
	
	protoboard<FieldT> pb;
	r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> pk;
	
	//mini shas
	
	
	sha256_two_to_one_hash_gadget<FieldT> * sha256_gadget;
	block_variable<FieldT>  *input;
	digest_variable<FieldT> *output;
	
	
	//bulk shas
	PoW_bulk_hash_gadget<FieldT, HashT> *ml;
	std::vector<block_variable<FieldT>> hasher_inputs;
	std::vector<digest_variable<FieldT>> hasher_outputs;
	
	
	
	string _CalculateHash(uint32_t _nIndex, uint32_t _nNonce,string sPrevHash,time_t _tTime,string _sData) const;
	string _CalculateHash( char* mBlock, uint32_t _nNonce) const;
    char* IP;
    

};

#endif