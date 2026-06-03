cmake_minimum_required(VERSION 3.20)
project(wfp_divert CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(WINDIVERT_DIR "${CMAKE_SOURCE_DIR}/windivert")

# Auto-detect target architecture
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(WINDIVERT_ARCH "x64")
    set(WINDIVERT_SYS "WinDivert64.sys")
else()
    set(WINDIVERT_ARCH "x86")
    set(WINDIVERT_SYS "WinDivert32.sys")
endif()

add_executable(wfp_divert
        src/main.cpp
        src/config.cpp
        src/process_info.cpp
        src/socks5_udp.cpp
        src/socks5_tcp.cpp
        src/divert.cpp
)

target_include_directories(wfp_divert PRIVATE
        include
        ${WINDIVERT_DIR}
)

target_link_libraries(wfp_divert PRIVATE
        ${WINDIVERT_DIR}/${WINDIVERT_ARCH}/WinDivert.lib
        ws2_32
        iphlpapi
        psapi
)

# Robust single-file copy operations for all CMake versions
add_custom_command(TARGET wfp_divert POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_DIR}/${WINDIVERT_ARCH}/WinDivert.dll"
        $<TARGET_FILE_DIR:wfp_divert>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_DIR}/${WINDIVERT_ARCH}/${WINDIVERT_SYS}"
        $<TARGET_FILE_DIR:wfp_divert>
)