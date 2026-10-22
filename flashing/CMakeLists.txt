cmake_minimum_required(VERSION 3.20)
project(flash_amd_port VERSION 5.0.879 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(flashamd_core
    src/core.cpp
    src/navi48_spi.cpp
)
target_include_directories(flashamd_core PUBLIC include)
target_compile_definitions(flashamd_core PRIVATE
    FLASHAMD_SOURCE_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
target_compile_options(flashamd_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)

add_executable(amdvbflash src/main.cpp)
target_link_libraries(amdvbflash PRIVATE flashamd_core)
target_compile_options(amdvbflash PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)

add_executable(R9700flash-dump src/r9700flash_dump_main.cpp)
target_link_libraries(R9700flash-dump PRIVATE flashamd_core)
target_compile_definitions(R9700flash-dump PRIVATE
    R9700FLASH_DUMP_SOURCE_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
target_compile_options(R9700flash-dump PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)

include(CTest)
if(BUILD_TESTING)
    add_executable(flashamd_core_tests tests/core_tests.cpp)
    target_link_libraries(flashamd_core_tests PRIVATE flashamd_core)
    target_compile_definitions(flashamd_core_tests PRIVATE
        FLASHAMD_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
    target_compile_options(flashamd_core_tests PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    add_test(NAME flashamd_core_tests COMMAND flashamd_core_tests)
    add_test(NAME flashamd_cli_version COMMAND amdvbflash --version)
    add_test(NAME flashamd_cli_help COMMAND amdvbflash --help)
    add_test(NAME flashamd_cli_smoke
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_smoke.sh $<TARGET_FILE:amdvbflash>)
    add_test(NAME r9700flash_dump_cli_help COMMAND R9700flash-dump --help)
endif()

install(TARGETS amdvbflash R9700flash-dump RUNTIME DESTINATION bin)
install(FILES data/asic_devices.csv data/EULA.txt data/original-help.txt DESTINATION share/flash-amd)
install(FILES docs/r9700flash-dump.md DESTINATION share/doc/flash-amd)
