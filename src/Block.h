//
// Created by Dave Nash on 20/10/2017.
//

#ifndef TESTCHAIN_BLOCK_H
#define TESTCHAIN_BLOCK_H

#include <cstdint>
#include <iostream>
#include <sstream>

using namespace std;

class Block {
public:
	uint32_t _nNonce;
    string sHash;
	string allblock;
    string sPrevHash;

    Block(uint32_t nIndexIn, const string &sDataIn);

    void MineBlock(uint32_t nDifficulty);
	 string _CalculateHash() const;
	 string _Returnheadernononce() const;
	 uint32_t _nIndex;
    
    string _sData;
    time_t _tTime;
	
    //static void prepareGenesisBlock(Block gen);
private:
    
   
};

#endif //TESTCHAIN_BLOCK_H
