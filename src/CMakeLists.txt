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
)
add_executable(
  helper

  Helpermain.cpp
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
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
target_include_directories(
  Controller

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

