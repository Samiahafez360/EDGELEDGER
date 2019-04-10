#include <iostream>
#include "Controller.h"
#include <string>
#include <chrono>
#include <ctime>   
#include "HelperNetworkUtilities.hpp"

int main(int argc, char **argv) {
	HelperNetworkUtilities hnu;
	hnu.zk = argc;
	hnu.hel_connect();
	return 0;
	}
	
	
	