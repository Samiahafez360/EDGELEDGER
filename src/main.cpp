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
#include <iostream>
#include "Controller.h"
#include <string>
#include <chrono>
#include <ctime>    

using namespace std;

using namespace libsnark;

typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;


void test_one_input() {

    protoboard<FieldT> pb;

    block_variable<FieldT>  input(pb, SHA256_block_size, "input");
    digest_variable<FieldT> output(pb, SHA256_digest_size, "output");
    sha256_two_to_one_hash_gadget<FieldT> sha256_gadget(pb, SHA256_block_size, input, output, "hash_gadget");

    sha256_gadget.generate_r1cs_constraints();

    
    //original place of next two lines
	//std::cout<<"starting to witness";
    //sha256_gadget.generate_r1cs_witness();

    const auto constraint_system = pb.get_constraint_system();

    // Create keypair
    auto keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

const libff::bit_vector hash_bv = libff::int_list_to_bits({0xc082e440, 0x671cd799, 0x8baf04c0, 0x22c07e03, 0x4b125ee7, 0xd28e0a59, 0x49e4b924, 0x5f5cf897}, 32);

    output.generate_r1cs_witness(hash_bv);

    //string 'hello world' 512 bytes.
    const libff::bit_vector input_bv = libff::int_list_to_bits({0x6c6c6568, 0x6f77206f, 0x00646c72, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}, 32);
    input.generate_r1cs_witness(input_bv);
    
	//new place of ext two lines
	std::cout<<"starting to witness";
    sha256_gadget.generate_r1cs_witness();
	
    // Create proof
    const auto proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
    proof.print_size();

    // Verify proof
    bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

    std::cout << "Number of R1cs constraints: " << constraint_system.num_constraints()  << std::endl;
    std::cout << "Verification status: "        << verified                             << std::endl;
}



int main (){
  //libff::print_header("Lets start");
  

    //	test_r1cs_gg_ppzksnark<default_r1cs_gg_ppzksnark_pp>(1000, 100);
	default_r1cs_ppzksnark_pp::init_public_params();
	test_one_input();
	
	return 0;
}
