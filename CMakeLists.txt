cmake_minimum_required(VERSION 3.15)
project(DriverDumper VERSION 1.0.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Options
option(BUILD_GUI "Build GUI version" ON)
option(BUILD_API "Build API version" ON)
option(BUILD_WEB "Build Web interface" ON)
option(BUILD_TESTS "Build tests" ON)
option(ENABLE_LOGGING "Enable logging" ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(CURL REQUIRED)
find_package(JSONCPP REQUIRED)
find_package(ZLIB REQUIRED)

if(BUILD_GUI)
    find_package(Qt5 COMPONENTS Core Gui Widgets REQUIRED)
endif()

if(BUILD_WEB)
    find_package(Crow REQUIRED)
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${CURL_INCLUDE_DIRS}
    ${JSONCPP_INCLUDE_DIRS}
    ${ZLIB_INCLUDE_DIRS}
)

# Source files
set(SOURCES
    src/core/driver_analysis.c
    src/core/memory_analysis.c
    src/core/security_analysis.c
    src/core/performance.c
    src/core/reporting.c
    src/core/integration.c
    src/core/monitoring.c
    src/core/advanced.c
    src/core/utils.c
    src/main.c
)

# Add executable
add_executable(driverdumper ${SOURCES})

# Link libraries
target_link_libraries(driverdumper
    ${OPENSSL_LIBRARIES}
    ${CURL_LIBRARIES}
    ${JSONCPP_LIBRARIES}
    ${ZLIB_LIBRARIES}
    Threads::Threads
)

if(BUILD_GUI)
    target_sources(driverdumper PRIVATE
        gui/mainwindow.cpp
        gui/driver_view.cpp
        gui/analysis_view.cpp
        gui/report_view.cpp
    )
    target_link_libraries(driverdumper
        Qt5::Core
        Qt5::Gui
        Qt5::Widgets
    )
endif()

if(BUILD_API)
    target_sources(driverdumper PRIVATE
        api/server.cpp
        api/routes.cpp
        api/handlers.cpp
    )
    target_link_libraries(driverdumper
        ${CROW_LIBRARIES}
    )
endif()

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Install
install(TARGETS driverdumper
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# Documentation
if(ENABLE_DOXYGEN)
    find_package(Doxygen REQUIRED)
    add_custom_target(docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
    )
endif() 