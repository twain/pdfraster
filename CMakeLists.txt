cmake_minimum_required(VERSION 3.9.0)
if (APPLE)
    set(CMAKE_OSX_ARCHITECTURES "i386;x86_64")
endif()
project(pdfraster C)

if (MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
endif()
if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
endif()

set(PDFRASTER_SHARED_LIB pdfraster)
set(PDFRASTER_STATIC_LIB pdfraster_static)
set(DEMO_RASTER_ENCODER demo_raster_encoder)

find_package(OpenSSL REQUIRED)

if (NOT ${OPENSSL_FOUND})
    message(FATAL_ERROR "OpenSSL was not found on system.")
endif ()

if (APPLE)
    include_directories("/usr/include:/usr/local/include")
    link_directories("/usr/lib:/usr/local/lib")
endif()

if (NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/icc_profile/srgb_icc_profile.h")
    execute_process(COMMAND make WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/icc_profile")
endif()

if (NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/demo_raster_encoder/bw_ccitt_data.h")
    execute_process(COMMAND make headers WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/demo_raster_encoder")
endif()

execute_process(COMMAND cp "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_digitalsignature/certificate.p12" "${CMAKE_CURRENT_BINARY_DIR}")

file(GLOB COMMON_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/common/*.c")
file(GLOB PDFRAS_READER_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_reader/*.c")
file(GLOB PDFRAS_WRITER_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_writer/*.c")
file(GLOB PDFRAS_DIGSIG_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_digitalsignature/*.c")
file(GLOB PDFRAS_ENCRYPTION_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_encryption/*.c")

file(GLOB COMMON_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/common/*.h")
file(GLOB PDFRAS_READER_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_reader/*.h")
#file(GLOB PDFRAS_WRITER_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_writer/*.h")
file(GLOB ICC_PROFILE_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/icc_profile/*.h")
file(GLOB PDFRAS_DISIG_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_digitalsignature/*.h")
file(GLOB PDFRAS_ENCRYPTION_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_encryption/*.h")

file(GLOB DEMO_RASTER_ENCODER_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/demo_raster_encoder/demo_raster_encoder.c")
file(GLOB DEMO_RASTER_ENCODER_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/demo_raster_encoder/*.h")

add_library(${PDFRASTER_SHARED_LIB} SHARED 
    ${COMMON_SRCS} 
    ${PDFRAS_READER_SRCS} 
    ${PDFRAS_WRITER_SRCS}
    ${PDFRAS_DIGSIG_SRCS}
    ${PDFRAS_ENCRYPTION_SRCS})
target_include_directories(${PDFRASTER_SHARED_LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/common")
target_include_directories(${PDFRASTER_SHARED_LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/icc_profile")
target_include_directories(${PDFRASTER_SHARED_LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_reader")
target_include_directories(${PDFRASTER_SHARED_LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_writer")
target_include_directories(${PDFRASTER_SHARED_LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_digitalsignature")
target_include_directories(${PDFRASTER_SHARED_LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_encryption")
target_link_libraries(${PDFRASTER_SHARED_LIB} ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})

add_library(${PDFRASTER_STATIC_LIB} STATIC 
    ${COMMON_SRCS} 
    ${PDFRAS_READER_SRCS} 
    ${PDFRAS_WRITER_SRCS}
    ${PDFRAS_DIGSIG_SRCS}
    ${PDFRAS_ENCRYPTION_SRCS})
target_include_directories(${PDFRASTER_STATIC_LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/common")
target_include_directories(${PDFRASTER_STATIC_LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/icc_profile")
target_include_directories(${PDFRASTER_STATIC_LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_reader")
target_include_directories(${PDFRASTER_STATIC_LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_writer")
target_include_directories(${PDFRASTER_STATIC_LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_digitalsignature")
target_include_directories(${PDFRASTER_STATIC_LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_encryption")
target_link_libraries(${PDFRASTER_STATIC_LIB} ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})

add_executable(${DEMO_RASTER_ENCODER} ${DEMO_RASTER_ENCODER_SRCS})
target_include_directories(${DEMO_RASTER_ENCODER} PUBLIC ${PDFRAS_WRITER_HEADERS})
target_link_libraries(${DEMO_RASTER_ENCODER} ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} ${PDFRASTER_STATIC_LIB} m)    

install(TARGETS ${PDFRASTER_SHARED_LIB} LIBRARY DESTINATION lib)
install(TARGETS ${PDFRASTER_STATIC_LIB} ARCHIVE DESTINATION lib)
install(DIRECTORY DESTINATION "include/pdfraster")
install(FILES ${COMMON_HEADERS} 
    ${PDFRAS_READER_HEADERS} 
    ${PDFRAS_WRITER_HEADERS} 
    ${ICC_PROFILE_HEADERS}
    ${PDFRAS_DISIG_HEADERS}
    ${PDFRAS_ENCRYPTION_HEADERS} DESTINATION "include/pdfraster")

set_property(TARGET ${PDFRASTER_SHARED_LIB} ${PDFRASTER_STATIC_LIB} ${DEMO_RASTER_ENCODER} PROPERTY C_STANDARD 99)