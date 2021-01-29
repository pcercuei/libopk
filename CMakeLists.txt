cmake_minimum_required(VERSION 3.4)
project(libopk LANGUAGES C VERSION 1.0)

include(GNUInstallDirs)

set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
	CACHE PATH "Installation directory for pkgconfig (.pc) files")

set(BUILD_SHARED_LIBS ON CACHE BOOL "Build shared libraries")
if (NOT BUILD_SHARED_LIBS)
	set(OPK_STATIC_CFLAGS -Dlibopk_STATIC)
endif (NOT BUILD_SHARED_LIBS)

find_package(PkgConfig REQUIRED)
pkg_check_modules(INI QUIET libini)
if (NOT INI_FOUND)
	message(FATAL_ERROR "Missing dependency: libini")
endif()

link_directories(${INI_LIBRARY_DIRS})
include_directories(${INI_INCLUDE_DIRS})

pkg_check_modules(ZLIB QUIET zlib)
if (ZLIB_FOUND)
	add_compile_definitions(USE_GZIP)
	link_directories(${ZLIB_LIBRARY_DIRS})
	include_directories(${ZLIB_INCLUDE_DIRS})
endif (ZLIB_FOUND)

add_library(opk libopk.c unsqfs.c opk.h unsqfs.h)
add_executable(opkinfo opkinfo.c)
add_executable(opkrun opkrun.c)

target_compile_definitions(opk PUBLIC ${INI_CFLAGS_OTHER} ${OPK_STATIC_CFLAGS})

if (CMAKE_COMPILER_IS_GNUCC)
	target_compile_options(opk PRIVATE -Wall -Wextra)
	if (NOT WIN32)
		target_compile_options(opk PRIVATE -fvisibility=hidden)
	endif()
endif()

set_target_properties(opk opkinfo opkrun PROPERTIES
	C_STANDARD 11
	C_STANDARD_REQUIRED ON
	C_EXTENSIONS OFF
)

set_target_properties(opk PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_VERSION_MAJOR}
	PUBLIC_HEADER opk.h
)

target_link_libraries(opk LINK_PRIVATE ${INI_LIBRARIES} ${ZLIB_LIBRARIES})
target_link_libraries(opkinfo opk)
target_link_libraries(opkrun opk)

configure_file(libopk.pc.cmakein libopk.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/libopk.pc DESTINATION "${INSTALL_PKGCONFIG_DIR}")

set(SETUP_PY ${CMAKE_SOURCE_DIR}/bindings/python/setup.py)
configure_file(${SETUP_PY}.cmakein ${SETUP_PY} @ONLY)

install(TARGETS opk opkinfo opkrun
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
