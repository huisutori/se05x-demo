PROJECT(se052f)

FILE(
    *.c
    *.h
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_ROOT}/model
    ${SE_PROJECT_ROOT}/simw-top/sss/inc
    ${SE_PROJECT_ROOT}/simw-top/hostlib/hostlib/inc
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    /usr/local/lib/libSSS_APIs.so
    /usr/local/lib/libsmCom.so
    /usr/local/lib/libse05x.so
    /usr/local/lib/libmwlog.so
)

ADD_EXECUTABLE(${PROJECT_NAME})
