# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.25

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
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
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/Link-RSUC

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/Link-RSUC/build

# Include any dependencies generated for this target.
include src/CMakeFiles/main.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include src/CMakeFiles/main.dir/compiler_depend.make

# Include the progress variables for this target.
include src/CMakeFiles/main.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/main.dir/flags.make

src/CMakeFiles/main.dir/main.c.o: src/CMakeFiles/main.dir/flags.make
src/CMakeFiles/main.dir/main.c.o: /root/Link-RSUC/src/main.c
src/CMakeFiles/main.dir/main.c.o: src/CMakeFiles/main.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/Link-RSUC/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/CMakeFiles/main.dir/main.c.o"
	cd /root/Link-RSUC/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/CMakeFiles/main.dir/main.c.o -MF CMakeFiles/main.dir/main.c.o.d -o CMakeFiles/main.dir/main.c.o -c /root/Link-RSUC/src/main.c

src/CMakeFiles/main.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/main.c.i"
	cd /root/Link-RSUC/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/Link-RSUC/src/main.c > CMakeFiles/main.dir/main.c.i

src/CMakeFiles/main.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/main.c.s"
	cd /root/Link-RSUC/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/Link-RSUC/src/main.c -o CMakeFiles/main.dir/main.c.s

src/CMakeFiles/main.dir/util.c.o: src/CMakeFiles/main.dir/flags.make
src/CMakeFiles/main.dir/util.c.o: /root/Link-RSUC/src/util.c
src/CMakeFiles/main.dir/util.c.o: src/CMakeFiles/main.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/Link-RSUC/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object src/CMakeFiles/main.dir/util.c.o"
	cd /root/Link-RSUC/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/CMakeFiles/main.dir/util.c.o -MF CMakeFiles/main.dir/util.c.o.d -o CMakeFiles/main.dir/util.c.o -c /root/Link-RSUC/src/util.c

src/CMakeFiles/main.dir/util.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/util.c.i"
	cd /root/Link-RSUC/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/Link-RSUC/src/util.c > CMakeFiles/main.dir/util.c.i

src/CMakeFiles/main.dir/util.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/util.c.s"
	cd /root/Link-RSUC/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/Link-RSUC/src/util.c -o CMakeFiles/main.dir/util.c.s

# Object files for target main
main_OBJECTS = \
"CMakeFiles/main.dir/main.c.o" \
"CMakeFiles/main.dir/util.c.o"

# External object files for target main
main_EXTERNAL_OBJECTS =

/root/Link-RSUC/bin/main: src/CMakeFiles/main.dir/main.c.o
/root/Link-RSUC/bin/main: src/CMakeFiles/main.dir/util.c.o
/root/Link-RSUC/bin/main: src/CMakeFiles/main.dir/build.make
/root/Link-RSUC/bin/main: /usr/local/lib/libtomcrypt.a
/root/Link-RSUC/bin/main: /usr/local/lib/libmclbn256.so
/root/Link-RSUC/bin/main: /usr/local/lib/libmcl.so
/root/Link-RSUC/bin/main: /usr/local/lib/libsecp256k1.so
/root/Link-RSUC/bin/main: src/CMakeFiles/main.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/Link-RSUC/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable /root/Link-RSUC/bin/main"
	cd /root/Link-RSUC/build/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/main.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/main.dir/build: /root/Link-RSUC/bin/main
.PHONY : src/CMakeFiles/main.dir/build

src/CMakeFiles/main.dir/clean:
	cd /root/Link-RSUC/build/src && $(CMAKE_COMMAND) -P CMakeFiles/main.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/main.dir/clean

src/CMakeFiles/main.dir/depend:
	cd /root/Link-RSUC/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/Link-RSUC /root/Link-RSUC/src /root/Link-RSUC/build /root/Link-RSUC/build/src /root/Link-RSUC/build/src/CMakeFiles/main.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/main.dir/depend

