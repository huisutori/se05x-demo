PROJECT(tls-server)

SET(PROJECT_ROOT "../../")
SET(SE_PROJECT_ROOT "../../../se05x-middleware")

ADD_SUBDIRECTORY(${PROJECT_ROOT}/port/se052f)
ADD_SUBDIRECTORY(${PROJECT_ROOT}/port/openssl)

FILE(
    *.c
    *.h 
)

TARGET_LINK_LIBRARIES(
    se052f
    se05x-openssl
)

CREATE_BINARY(${PROJECT_NAME})
