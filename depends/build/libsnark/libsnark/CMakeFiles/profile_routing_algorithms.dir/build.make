# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/samia/libsnarktut/depends

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/samia/libsnarktut/depends/build

# Include any dependencies generated for this target.
include libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/depend.make

# Include the progress variables for this target.
include libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/progress.make

# Include the compile flags for this target's objects.
include libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/flags.make

libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o: libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/flags.make
libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o: ../libsnark/libsnark/common/routing_algorithms/profiling/profile_routing_algorithms.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/samia/libsnarktut/depends/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o"
	cd /home/samia/libsnarktut/depends/build/libsnark/libsnark && /usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o -c /home/samia/libsnarktut/depends/libsnark/libsnark/common/routing_algorithms/profiling/profile_routing_algorithms.cpp

libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.i"
	cd /home/samia/libsnarktut/depends/build/libsnark/libsnark && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/samia/libsnarktut/depends/libsnark/libsnark/common/routing_algorithms/profiling/profile_routing_algorithms.cpp > CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.i

libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.s"
	cd /home/samia/libsnarktut/depends/build/libsnark/libsnark && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/samia/libsnarktut/depends/libsnark/libsnark/common/routing_algorithms/profiling/profile_routing_algorithms.cpp -o CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.s

libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o.requires:

.PHONY : libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o.requires

libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o.provides: libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o.requires
	$(MAKE) -f libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/build.make libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o.provides.build
.PHONY : libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o.provides

libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o.provides.build: libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o


# Object files for target profile_routing_algorithms
profile_routing_algorithms_OBJECTS = \
"CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o"

# External object files for target profile_routing_algorithms
profile_routing_algorithms_EXTERNAL_OBJECTS =

libsnark/libsnark/profile_routing_algorithms: libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o
libsnark/libsnark/profile_routing_algorithms: libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/build.make
libsnark/libsnark/profile_routing_algorithms: libsnark/libsnark/libsnark.a
libsnark/libsnark/profile_routing_algorithms: libsnark/depends/libff/libff/libff.a
libsnark/libsnark/profile_routing_algorithms: /usr/lib/x86_64-linux-gnu/libgmp.so
libsnark/libsnark/profile_routing_algorithms: /usr/lib/x86_64-linux-gnu/libgmp.so
libsnark/libsnark/profile_routing_algorithms: /usr/lib/x86_64-linux-gnu/libgmpxx.so
libsnark/libsnark/profile_routing_algorithms: libsnark/depends/libzm.a
libsnark/libsnark/profile_routing_algorithms: libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/samia/libsnarktut/depends/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable profile_routing_algorithms"
	cd /home/samia/libsnarktut/depends/build/libsnark/libsnark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/profile_routing_algorithms.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/build: libsnark/libsnark/profile_routing_algorithms

.PHONY : libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/build

libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/requires: libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o.requires

.PHONY : libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/requires

libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/clean:
	cd /home/samia/libsnarktut/depends/build/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/profile_routing_algorithms.dir/cmake_clean.cmake
.PHONY : libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/clean

libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/depend:
	cd /home/samia/libsnarktut/depends/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/samia/libsnarktut/depends /home/samia/libsnarktut/depends/libsnark/libsnark /home/samia/libsnarktut/depends/build /home/samia/libsnarktut/depends/build/libsnark/libsnark /home/samia/libsnarktut/depends/build/libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libsnark/libsnark/CMakeFiles/profile_routing_algorithms.dir/depend

