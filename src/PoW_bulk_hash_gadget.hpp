/** @file
 *****************************************************************************
 Declaration of interfaces for the pow by a range.
 The gadget check the following: given a range r (integer), a starting value
 (integer), a block b and a difficulty d (String), checks if the range includes
 the nonce value that meets the difficulty.

 *****************************************************************************
 * @author     This file is written by samia hafez as a partt of the edge ledger
                depends on the libsnark library.
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef POW_BULK_HASH_GADGET_HPP_
#define POW_BULK_HASH_GADGET_HPP_

#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/crh_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/digest_selector_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>

namespace libsnark {

template<typename FieldT, typename HashT>
class PoW_bulk_hash_gadget: public gadget<FieldT> {
// This gadget only prooves the hash computation 
// no correct advancement of nonce is proved
// no correct difficulty comparison is proved  
	
private:
	// vector of hasher gadgets
    std::vector<HashT> hashers;
public:

	const size_t digest_size;
    const size_t srange;
    
	//a vector of block variables which 
	std::vector<block_variable<FieldT>> hasher_inputs;
    std::vector<digest_variable<FieldT>> hasher_outputs;
       
	
    PoW_bulk_hash_gadget(protoboard<FieldT> &pb,
                                  const size_t srange,
                                  const std::vector<block_variable<FieldT>> &hasher_inputs,
                                  const std::vector<digest_variable<FieldT>> &hasher_outputs,
                                  const std::string &annotation_prefix):
	gadget<FieldT>(pb, annotation_prefix),     
    digest_size(HashT::get_digest_len()),
    srange(srange),
    hasher_inputs(hasher_inputs),
    hasher_outputs(hasher_outputs)
	{
		printf("Checkpoint 4\n");
		assert(srange > 0);
		assert (hasher_inputs.size() == srange);
		assert (hasher_outputs.size() == srange);
		
		for (size_t i = 0; i < srange; ++i)
		{
            //Add the hash value 
			hashers.emplace_back(HashT(this->pb, digest_size, hasher_inputs[i], hasher_outputs[i], 
								FMT(this->annotation_prefix, " load_hashers_%zu", i)));
		}
										
	}

    void generate_r1cs_constraints(){
		for (size_t i = 0; i < srange; ++i)
		{
		
        // Note that we check root outside and have enforced booleanity of path.left_digests/path.right_digests outside in path.generate_r1cs_constraints
        hashers[i].generate_r1cs_constraints(false);
		}
		
	}
    void generate_r1cs_witness(){
		std::cout <<"witnessing in the bulk sha gadget";
		for (int i = 0; i <srange ; i++)
		{
			hashers[i].generate_r1cs_witness();
		
		}
		std::cout<<"end of witnessing in the bulk sha gadget";
		
	}

    
    /* for debugging purposes */
    static size_t expected_constraints(const size_t srange){
		
		const size_t hasher_constraints = srange * HashT::expected_constraints(false);
		return hasher_constraints + srange;

	}
};

} // libsnark


#endif // POW_BULK_HASH_GADGET_HPP_