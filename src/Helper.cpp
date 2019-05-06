
#include "Helper.h"
#include "sha256.h"
#include "Block.h"
#include <chrono>

Helper::Helper(){
	
	input = new  block_variable<FieldT>(pb, SHA256_block_size, "input");
	output = new digest_variable<FieldT>(pb, SHA256_digest_size, "output");
    sha256_gadget = new sha256_two_to_one_hash_gadget<FieldT> (pb, SHA256_block_size, *input, *output, "hash_gadget");
	sha256_gadget->generate_r1cs_constraints();
}

Helper::Helper(int sizofgad){
	
	
	for (int i = 0; i < sizofgad ;i++){
		block_variable<FieldT>  input_bulk(pb, SHA256_block_size, FMT("", "hashers inputs", i));
		digest_variable<FieldT> output_bulk(pb, SHA256_digest_size, FMT("", "hashers outputs", i));
		hasher_inputs.push_back(input_bulk);
		hasher_outputs.push_back(output_bulk);
    
	}
	
	ml = new PoW_bulk_hash_gadget<FieldT, HashT>(pb, sizofgad, hasher_inputs,hasher_outputs, "Bulk hasher");

	ml->generate_r1cs_constraints();
}
int Helper::minenozk(uint32_t _sNonce, uint32_t range, uint32_t nDifficulty,Block mBlock,std::chrono::system_clock::time_point starttime)
{

	char cstr[nDifficulty + 1];
    for (uint32_t i = 0; i < nDifficulty; ++i)
    {
        cstr[i] = '0';
    }
    cstr[nDifficulty] = '\0';
	string str(cstr);
	uint32_t _nNonce = _sNonce;
	string sHash;
    do
    {
        sHash = _CalculateHash(mBlock._nIndex, _nNonce,mBlock.sPrevHash,mBlock._tTime,mBlock._sData);
		_nNonce++;
		if (sHash.substr(0, nDifficulty) == str){
			cout<<"\n FOOOOUUUUNNNNNNDDDDDDDD after"<<_nNonce-_sNonce<< "trials" <<_nNonce<<"\n";
			
			auto end = std::chrono::system_clock::now();
			
			std::chrono::duration<double> elapsed_seconds = end-starttime;
        	std::cout << "^^^^^^^^^^^^^^^^@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%%finished computation at " << "elapsed time: " << elapsed_seconds.count() << "s\n";
			return _nNonce-1;
		}
    }
    while (_sNonce+range >= _nNonce);
	cout<<"\n not FOOOOUUUUNNNNNNDDDD";
    return -1;
	
	
}
int Helper::minenozk_net(uint32_t _sNonce, uint32_t range,uint32_t nDifficulty,char* mBlock,long long starttime){
	
	char cstr[nDifficulty + 1];
    for (uint32_t i = 0; i < nDifficulty; ++i)
    {
        cstr[i] = '0';
    }
    cstr[nDifficulty] = '\0';
	string str(cstr);
	uint32_t _nNonce = _sNonce;
	string sHash;
	printf("Starting to submine %d  and    %d\n", _sNonce, range+_sNonce);
    do
    {
        sHash = _CalculateHash( mBlock, _nNonce);
		_nNonce++;
		if (sHash.substr(0, nDifficulty) == str){
			cout<<"\n FOOOOUUUUNNNNNNDDDDDDDD after"<<_nNonce-_sNonce<< "trials" <<_nNonce<<"\n";
			
			//auto end = std::chrono::system_clock::now();
			
			//double elapsed_seconds = static_cast<long int> (std::chrono::system_clock::to_time_t(end))-starttime;
        	//std::cout << "^^^^^^^^^^^^^^^^@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%%finished computation at " << "elapsed time: " << elapsed_seconds << "s\n";
			return _nNonce-1;
		}
    }
    while (_sNonce+range >= _nNonce);
	cout<<"\n not FOOOOUUUUNNNNNNDDDD";
    return -1;
	
	
}
inline string Helper::_CalculateHash(uint32_t _nIndex, uint32_t _nNonce,string sPrevHash,time_t _tTime,string _sData) const
{
    stringstream ss;
    ss << _nIndex << sPrevHash << _tTime << _sData << _nNonce;
    //cout << "\n choose one" << &ss;
    return sha256(ss.str());
}
inline string Helper::_CalculateHash( char* mBlock, uint32_t _nNonce)const{ 
	stringstream ss;
    ss << mBlock << _nNonce;
    return sha256(ss.str());
}
int Helper::minezk(uint32_t start, uint32_t range,uint32_t nDifficulty,char* mBlock,r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> pk,long long starttime)
{
	
	//already done in constructor
	
	//protoboard<FieldT> pb;

    //block_variable<FieldT>  input(pb, SHA256_block_size, "input");
    //digest_variable<FieldT> output(pb, SHA256_digest_size, "output");
    //sha256_two_to_one_hash_gadget<FieldT> sha256_gadget(pb, SHA256_block_size, input, output, "hash_gadget");

    //sha256_gadget.generate_r1cs_constraints();
	printf ("zk at helper \n");
			
	
	//do ordinary work
	
	char cstr[nDifficulty + 1];
    for (uint32_t i = 0; i < nDifficulty; ++i)
	{
        cstr[i] = '0';
    }
    cstr[nDifficulty] = '\0';
	string str(cstr);
	uint32_t _nNonce = start;
	string sHash;
    do
    {
		
		libff::print_header("Mining loooooooooppppp");
		
		stringstream ss;
		ss <<mBlock << _nNonce;
		cout<<mBlock << _nNonce;
		sHash= sha256(ss.str());
		cout<<"\n HO HO HO";
		
		std::vector<bool> myVec;
		for(auto a : ss.str()) myVec.push_back(a =='1');
		const libff::bit_vector input_bv = myVec;
		input->generate_r1cs_witness(input_bv);
		cout<<"\n HO HO HO";
		
		std::vector<bool> myhashVec;
		for(auto a : sHash) myhashVec.push_back(a =='1');
		const libff::bit_vector hash_bv =myhashVec;
		output->generate_r1cs_witness(hash_bv);
		sha256_gadget->generate_r1cs_witness();
		_nNonce++;
		
		proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(pk, pb.primary_input(), pb.auxiliary_input());
		proof.print_size();
		
		if (sHash.substr(0, nDifficulty) == str){
			cout<<"\n FOOOOUUUUNNNNNNDDDDDDDD after"<<_nNonce-start<< "trials" <<_nNonce<<"\n";
			
			auto end = std::chrono::system_clock::now();
			long long int endt = static_cast<long long int> (std::chrono::system_clock::to_time_t(end));
	
			long long int duration = endt-starttime;
        	std::cout << "^^^^^^^^^^^^^^^^@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%%finished computation at " << "elapsed time: " << duration << "s\n";
			
			return _nNonce-1;
		}
    }
    while (start+range >= _nNonce);
	cout<<"\n not FOOOOUUUUNNNNNNDDDD";
    return -1;


}

int Helper::minezk_bulk(int srange,uint32_t start, uint32_t range,uint32_t nDifficulty,long long starttime,char* mBlock)
{
	//do ordinary work
	
	char cstr[nDifficulty + 1];
	for (uint32_t i = 0; i < nDifficulty; ++i)
	{
		cstr[i] = '0';
	}
	cstr[nDifficulty] = '\0';
	string str(cstr);
	uint32_t _nNonce = start;
	string sHash;
	std::vector<bool> myVec;
	std::vector<bool> myhashVec;
	int i=0;
	
	auto start_exp = std::chrono::system_clock::now();
	std::time_t time_before_exp = std::chrono::system_clock::to_time_t(start_exp);
	std::cout << "\n time_before_experiment  at " << std::ctime(&time_before_exp);
	double lastproofduration =0.0 ;
	
	
	do
	{	
		auto start_generating_vectors = std::chrono::system_clock::now();	
		libff::print_header("Mining loooooooooppppp");
		//maintain index of the sha gadget 
		i= i % srange;
		
		stringstream ss;
		ss << mBlock << _nNonce;
		sHash= sha256(ss.str());
			
		
		for(auto a : ss.str()) myVec.push_back(a =='1');
		const libff::bit_vector input_bv = myVec;
		hasher_inputs[i].generate_r1cs_witness(input_bv);
	
		
		for(auto a : sHash) myhashVec.push_back(a =='1');
		const libff::bit_vector hash_bv =myhashVec;
		hasher_outputs[i].generate_r1cs_witness(hash_bv);
		auto end_generating_vectors = std::chrono::system_clock::now();
		
		
		std::chrono::duration<double> vecduration =end_generating_vectors-start_generating_vectors;
			
		std::cout << "\n time taken to add the hashes to the vectors " <<vecduration.count()<<"\n";
			
		// I am only proving after the bulk index 
		if (i == (srange-1)){
			
			std::cout << "\n @" <<_nNonce<< " witnessing and proving" << _nNonce<<"\n";
			auto start_witprv = std::chrono::system_clock::now();
			
			//witnessing
			ml->generate_r1cs_witness();
			auto end_wit = std::chrono::system_clock::now();
			std::chrono::duration<double> witduration = end_wit-start_witprv;
			
			//proving
			auto proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(pk, pb.primary_input(), pb.auxiliary_input());
			auto end_prv = std::chrono::system_clock::now();
			std::chrono::duration<double> prvduration = end_prv-end_wit;
			std::cout << "\n time taken to witness " <<witduration.count()<< "  \n time taken to prove "<<prvduration.count()<<"\n";
			lastproofduration = prvduration.count();
			proof.print_size();
			proofs.insert(pair<int,r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp>>(_nNonce, proof));
			
		}
		
		_nNonce++;
		i++;
	}
	while (start+range >= _nNonce);
	auto end_exp = std::chrono::system_clock::now();
		
	std::time_t time_after_exp = std::chrono::system_clock::to_time_t(end_exp);
	std::chrono::duration<double> expduration = end_exp-start_exp;
	std::cout << "Time after experimenting with Bulk shas at " << std::ctime(&time_after_exp);    	
	std::cout<<"\n Time passed for experimentation for Bulk"<< srange << "SHAgadget with range " << range <<"  is  "<< expduration.count()<<" seconds\n";

	std::cout<<"\n Time passed for experimentation for Bulk without last proof"<< srange << "SHAgadget with range " << range <<"  is  "<< expduration.count()-lastproofduration <<" seconds\n";

		
	return -1;
}

/*void Helper::setVK (bacs_ppzksnark_verification_key vk){
  verificationKey = vk;
}*/
  /*char* Helper::getIP(){
    return IP;
  }*/
