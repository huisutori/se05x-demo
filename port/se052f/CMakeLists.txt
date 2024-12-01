PROJECT(se052f)

SET(SE_MIDDLEWARE_ROOT "${CMAKE_SOURCE_DIR}/se05x-middleware/simw-top")
SET(SE_MIDDLEWARE_BUILD_ROOT "${CMAKE_SOURCE_DIR}/se05x-middleware/simw-top_build/raspbian_native_se050_t1oi2c")

FILE(
    GLOB
    files
    *.c
)

ADD_LIBRARY(
    ${PROJECT_NAME}
    SHARED
    ${files}
)

ADD_DEFINITIONS(-DSSS_USE_FTR_FILE)
INCLUDE(${SE_MIDDLEWARE_BUILD_ROOT}/cmake_options_installed.cmake)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${SE_MIDDLEWARE_BUILD_ROOT}
    ${SE_MIDDLEWARE_ROOT}/sss/inc
    ${SE_MIDDLEWARE_ROOT}/hostlib/hostLib/inc
    ${SE_MIDDLEWARE_ROOT}/hostlib/hostLib/platform/inc
    IF(NOT SSS_HAVE_KSDK)
        ${SE_MIDDLEWARE_ROOT}/sss/port/default
    ELSE()
        ${SE_MIDDLEWARE_ROOT}/sss/port/ksdk
    ENDIF()
    ${SE_MIDDLEWARE_ROOT}/hostlib/hostLib/libCommon/infra
    ${SE_MIDDLEWARE_ROOT}/hostlib/hostLib/libCommon/log
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    PRIVATE
    /usr/local/lib/libSSS_APIs.so
    /usr/local/lib/libsmCom.so
    /usr/local/lib/libse05x.so
    /usr/local/lib/libmwlog.so
    /usr/local/lib/libsss_engine.so
    /usr/local/lib/libsssapisw.so
)

