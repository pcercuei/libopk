cmake_minimum_required(VERSION 2.8.8)
project(libopk C)

set(VERSION "1.0")

set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib" 
	CACHE PATH "Installation directory for libraries")
set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include"
	CACHE PATH "Installation directory for headers")
set(INSTALL_PKGCONFIG_DIR "${INSTALL_LIB_DIR}/pkgconfig"
	CACHE PATH "Installation directory for pkgconfig (.pc) files")

find_package(PkgConfig)
pkg_check_modules(LIBINI QUIET libini)
if (NOT LIBINI_FOUND)
	message(FATAL_ERROR "'libini' must be installed first!")
endif()

set(LIBOPK_PC ${CMAKE_CURRENT_BINARY_DIR}/libopk.pc)
configure_file(libopk.pc.cmakein ${LIBOPK_PC} @ONLY)
install(FILES ${LIBOPK_PC} DESTINATION "${INSTALL_PKGCONFIG_DIR}")

set(SETUP_PY ${CMAKE_CURRENT_SOURCE_DIR}/python/setup.py)
configure_file(python/setup.py.cmakein ${SETUP_PY} @ONLY)

set(LIBOPK_CFILES libopk.c unsqfs.c)
set(LIBOPK_HEADERS opk.h)

#add_definitions(${LIBINI_CFLAGS_OTHER})
set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} ${LIBINI_CFLAGS_OTHER})
include_directories(${LIBINI_INCLUDE_DIRS})

add_library(opk SHARED ${LIBOPK_CFILES} ${LIBOPK_HEADERS})
add_library(opkstatic STATIC ${LIBOPK_CFILES} ${LIBOPK_HEADERS})
set_target_properties(opk opkstatic PROPERTIES OUTPUT_NAME opk)
set_target_properties(opk PROPERTIES VERSION ${VERSION})

set_property(TARGET opk opkstatic APPEND_STRING PROPERTY COMPILE_FLAGS "-std=c11 ")

target_link_libraries(opk ${LIBINI_LIBRARIES})
target_link_libraries(opkstatic ${LIBINI_LIBRARIES})

if (NOT SKIP_INSTALL_HEADERS AND NOT SKIP_INSTALL_ALL)
	install(FILES ${LIBOPK_HEADERS} DESTINATION "${INSTALL_INC_DIR}")
endif()

if(NOT SKIP_INSTALL_LIBRARIES AND NOT SKIP_INSTALL_ALL)
    install(TARGETS opk opkstatic
        ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR}")
endif()
