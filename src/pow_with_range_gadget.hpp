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

#ifndef POW_WITH_RANGE_GADGET_HPP_
#define POW_WITH_RANGE_GADGET_HPP_

#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/crh_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/digest_selector_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>

namespace libsnark {

template<typename FieldT, typename HashT>
class pow_with_range_gadget : public gadget<FieldT> {
private:

    std::vector<HashT> hashers;
    std::vector<block_variable<FieldT> > hasher_inputs;
    std::vector<digest_selector_gadget<FieldT> > propagators;
    std::vector<digest_variable<FieldT> > internal_output;

    std::shared_ptr<digest_variable<FieldT> > computed_root;
    std::shared_ptr<bit_vector_copy_gadget<FieldT> > check_root;

public:

    const size_t digest_size;
    const size_t range;
    //@@@@@@
    pb_linear_combination_array<FieldT> address_bits;
	digest_variable<FieldT> range;
    digest_variable<FieldT> snonce;
    digest_variable<FieldT> block;
    digest_variable<FieldT> difficulty;

    //@@@
    pb_linear_combination<FieldT> read_successful;

    merkle_tree_check_read_gadget(protoboard<FieldT> &pb,
                                  const size_t range,
                                  const pb_linear_combination_array<FieldT> &address_bits,
                                  const digest_variable<FieldT > &range,
                                  const digest_variable<FieldT> &snonce,
                                  const digest_variable<FieldT> &block,
                                  const digest_variable<FieldT> &difficulty,
                                  const pb_linear_combination<FieldT> &read_successful,
                                  const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();

    static size_t root_size_in_bits();
    /* for debugging purposes */
    static size_t expected_constraints(const size_t range);
};

template<typename FieldT, typename HashT>
void test_pow_with_range_gadget();

} // libsnark

#include <libsnark/gadgetlib1/gadgets/merkle_tree/pow_with_range_gadget.tcc>

#endif // MERKLE_TREE_CHECK_READ_GADGET_HPP_
