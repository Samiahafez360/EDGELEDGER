include_directories(.)

add_executable(
  main

  main.cpp
Controller.h
  Controller.cpp
  Helper.h
  Helper.cpp
  ControllerNetworkUtilities.hpp
HelperNetworkUtilities.hpp

  Block.h
  Block.cpp
sha256.h
sha256.cpp
PoW_bulk_hash_gadget.hpp

)
add_executable(
  helper

Helpermain.cpp
Helper.h
  Helper.cpp
Controller.h
  Controller.cpp
ControllerNetworkUtilities.hpp
  HelperNetworkUtilities.hpp
  Block.h
  Block.cpp
  sha256.h
  sha256.cpp
  PoW_bulk_hash_gadget.hpp
   
)
add_executable(
  Controller

  Controllermain.cpp
  Controller.h
  Controller.cpp
  Helper.h
  Helper.cpp
  ControllerNetworkUtilities.hpp
  HelperNetworkUtilities.hpp
  Block.h
  Block.cpp
  sha256.h
  sha256.cpp
  PoW_bulk_hash_gadget.hpp
)
target_link_libraries(
  helper

  snark


)
target_link_libraries(
  Controller

  snark

)
target_link_libraries(
  main

  snark

)
target_include_directories(
  main

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
target_include_directories(
  helper

  PUBLIC
	PUBLIC/src
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
target_include_directories(
  Controller

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

