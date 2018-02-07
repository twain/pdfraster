cmake_minimum_required(VERSION 3.9.0)
if (APPLE)
    set(CMAKE_OSX_ARCHITECTURES "i386;x86_64")
endif()
project(pdfraster C)

set(PDFRASTER_SHARED_LIB pdfraster)
set(PDFRASTER_STATIC_LIB pdfraster_static)

find_package(OpenSSL REQUIRED)

if (NOT ${OPENSSL_FOUND})
    message(FATAL_ERROR "OpenSSL was not found on system.")
endif ()

if (APPLE)
    include_directories("/usr/include:/usr/local/include")
    link_directories("/usr/lib:/usr/local/lib")
endif()

if (NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/icc_profile/srgb_icc_profile.h")
    message(FATAL_ERROR "icc_profile/srgb_icc_profile.h does not exist.\n
    Please, build icc_profile and run its binary.")
endif()

file(GLOB COMMON_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/common/*.c")
file(GLOB PDFRAS_READER_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_reader/*.c")
file(GLOB PDFRAS_WRITER_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_writer/*.c")
file(GLOB PDFRAS_DIGSIG_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_digitalsignature/*.c")
file(GLOB PDFRAS_ENCRYPTION_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_encryption/*.c")

file(GLOB COMMON_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/common/*.h")
file(GLOB PDFRAS_READER_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_reader/*.h")
file(GLOB PDFRAS_WRITER_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_writer/*.h")
file(GLOB ICC_PROFILE_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/icc_profile/*.h")
file(GLOB PDFRAS_DISIG_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_digitalsignature/*.h")
file(GLOB PDFRAS_ENCRYPTION_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/pdfras_encryption/*.h")

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

install(TARGETS ${PDFRASTER_SHARED_LIB} LIBRARY DESTINATION lib)
install(TARGETS ${PDFRASTER_STATIC_LIB} ARCHIVE DESTINATION lib)
install(DIRECTORY DESTINATION "include/pdfraster")
install(FILES ${COMMON_HEADERS} 
    ${PDFRAS_READER_HEADERS} 
    ${PDFRAS_WRITER_HEADERS} 
    ${ICC_PROFILE_HEADERS}
    ${PDFRAS_DISIG_HEADERS}
    ${PDFRAS_ENCRYPTION_HEADERS} DESTINATION "include/pdfraster")
