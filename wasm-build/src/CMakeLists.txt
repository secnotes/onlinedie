cmake_minimum_required(VERSION 3.15)
project(die_wasm CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(EMSCRIPTEN)
    message(STATUS "Building for WebAssembly")
    set(CMAKE_EXECUTABLE_SUFFIX ".js")
endif()

add_executable(diec die_wasm.cpp)

if(EMSCRIPTEN)
    target_link_options(diec PRIVATE
        -O3
        -sWASM
        -sEXPORT_ES6
        -sMODULARIZE
        -sEXPORT_NAME=createDieModule
        -sALLOW_MEMORY_GROWTH
        -sINITIAL_MEMORY=16MB
        -sSTACK_SIZE=1MB
        -sFORCE_FILESYSTEM
        -sEXPORTED_RUNTIME_METHODS=FS,UTF8ToString,allocate,ALLOC_NORMAL
        -sEXPORTED_FUNCTIONS=_detect_file,_detect_file_text,_detect_file_xml,_calculate_entropy,_get_file_format,_malloc,_free
    )

    add_custom_command(TARGET diec POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/diec.js ${CMAKE_SOURCE_DIR}/../../docs/wasm/diec.js
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/diec.wasm ${CMAKE_SOURCE_DIR}/../../docs/wasm/diec.wasm
        COMMENT "Copying WASM to docs/wasm"
    )
endif()