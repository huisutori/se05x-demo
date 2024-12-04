#include "fsl_sss_se05x_apis.h"
#include "fsl_sss_openssl_apis.h"
#include "nxScp03_Types.h"
#include "ax_reset.h"
#include "se05x_demo_config.h"
#include "model/secure_element.h"

#ifndef SECURE_ELEMENT_I2C_DEVICE
    #define SECURE_ELEMENT_I2C_DEVICE "/dev/i2c-1"
#endif

#define PLATFORM_SCP_KVN (0x0B)
#define PLATFORM_SCP_KEYSTORE_ID (0x01)
#define PLATFORM_SCP_AUTH_ENC_KEY_ID (0x01)
#define PLATFORM_SCP_AUTH_MAC_KEY_ID (0x02)
#define PLATFORM_SCP_SESSION_ENC_KEY_ID (0x03)
#define PLATFORM_SCP_SESSION_MAC_KEY_ID (0x04)
#define PLATFORM_SCP_SESSION_RMAC_KEY_ID (0x05)

#define PLATFORM_SCP_KEY_SIZE 16
#define PLATFORM_SCP_MAX_KEY_SIZE 52
static uint8_t platform_scp_enc_key[PLATFORM_SCP_KEY_SIZE] = {
    0x3a, 0xe4, 0x41, 0xc7, 0x47, 0xe3, 0x2e, 0xbc, 0x16, 0xb3, 0xbb, 0x2d, 0x84, 0x3c, 0x6d, 0xd8,
};
static uint8_t platform_scp_mac_key[PLATFORM_SCP_KEY_SIZE] = {
    0x6c, 0x18, 0xf3, 0xd0, 0x8f, 0xee, 0x1c, 0xb9, 0x6a, 0x3c, 0x8d, 0xe5, 0xd3, 0x53, 0x8a, 0xaa,
};

static sss_session_t se_session;
static sss_session_t host_session;

static sss_key_store_t platform_scp_keystore;

static NXSCP03_StaticCtx_t platform_scp_auth_key = {
    .keyVerNo = PLATFORM_SCP_KVN,
};
static NXSCP03_DynCtx_t platform_scp_session_key = {
    .authType = kSSS_AuthType_SCP03,
};

static int setup_host(void)
{
    int status = sss_host_session_open(&host_session, kType_SSS_OpenSSL, 0, 
                                       kSSS_ConnectionType_Plain, NULL);
    if (status != kStatus_SSS_Success) {
        return -1;
    }

    status = sss_host_key_store_context_init(&platform_scp_keystore, &host_session);
    if (status != kStatus_SSS_Success) {
        return -2;
    }

    status = sss_host_key_store_allocate(&platform_scp_keystore, PLATFORM_SCP_KEYSTORE_ID);
    if (status != kStatus_SSS_Success) {
        return -3;
    }

    status = sss_host_key_object_init(&platform_scp_auth_key.Enc, &platform_scp_keystore);
    if (status != kStatus_SSS_Success) {
        return -4;
    }

    status = sss_host_key_object_allocate_handle(&platform_scp_auth_key.Enc, PLATFORM_SCP_AUTH_ENC_KEY_ID,
                                                 kSSS_KeyPart_Default, kSSS_CipherType_AES,
                                                 PLATFORM_SCP_MAX_KEY_SIZE, kKeyObject_Mode_Transient);
    if (status != kStatus_SSS_Success) {
        return -5;
    }

    status = sss_host_key_store_set_key(&platform_scp_keystore, &platform_scp_auth_key.Enc, 
                                        platform_scp_enc_key, PLATFORM_SCP_KEY_SIZE, 
                                        PLATFORM_SCP_KEY_SIZE * 8, NULL, 0);
    if (status != kStatus_SSS_Success) {
        return -6;
    }

    status = sss_host_key_object_init(&platform_scp_auth_key.Mac, &platform_scp_keystore);
    if (status != kStatus_SSS_Success) {
        return -7;
    }

    status = sss_host_key_object_allocate_handle(&platform_scp_auth_key.Mac, PLATFORM_SCP_AUTH_MAC_KEY_ID,
                                                 kSSS_KeyPart_Default, kSSS_CipherType_AES,
                                                 PLATFORM_SCP_MAX_KEY_SIZE, kKeyObject_Mode_Transient);

    if (status != kStatus_SSS_Success) {
        return -8;
    }

    status = sss_host_key_store_set_key(&platform_scp_keystore, &platform_scp_auth_key.Mac, 
                                        platform_scp_mac_key, PLATFORM_SCP_KEY_SIZE, 
                                        PLATFORM_SCP_KEY_SIZE * 8, NULL, 0);
    if (status != kStatus_SSS_Success) {
        return -9;
    }

    status = sss_host_key_object_init(&platform_scp_session_key.Enc, 
                                      &platform_scp_keystore);
    if (status != kStatus_SSS_Success) {
        return -10;
    }

    status = sss_host_key_object_allocate_handle(&platform_scp_session_key.Enc,
                                                 PLATFORM_SCP_SESSION_ENC_KEY_ID,
                                                 kSSS_KeyPart_Default,
                                                 kSSS_CipherType_AES,
                                                 PLATFORM_SCP_MAX_KEY_SIZE,
                                                 kKeyObject_Mode_Transient);
    if (status != kStatus_SSS_Success) {
        return -11;
    }

    status = sss_host_key_object_init(&platform_scp_session_key.Mac, 
                                      &platform_scp_keystore);
    if (status != kStatus_SSS_Success) {
        return -12;
    }

    status = sss_host_key_object_allocate_handle(&platform_scp_session_key.Mac,
                                                 PLATFORM_SCP_SESSION_MAC_KEY_ID,
                                                 kSSS_KeyPart_Default,
                                                 kSSS_CipherType_AES,
                                                 PLATFORM_SCP_MAX_KEY_SIZE,
                                                 kKeyObject_Mode_Transient);
    if (status != kStatus_SSS_Success) {
        return -13;
    }

    status = sss_host_key_object_init(&platform_scp_session_key.Rmac, 
                                      &platform_scp_keystore);
    if (status != kStatus_SSS_Success) {
        return -14;
    }

    status = sss_host_key_object_allocate_handle(&platform_scp_session_key.Rmac,
                                                 PLATFORM_SCP_SESSION_RMAC_KEY_ID,
                                                 kSSS_KeyPart_Default,
                                                 kSSS_CipherType_AES,
                                                 PLATFORM_SCP_MAX_KEY_SIZE,
                                                 kKeyObject_Mode_Transient);
    if (status != kStatus_SSS_Success) {
        return -15;
    }

    return 0;
}

static int setup_se(void)
{
    SE_Connect_Ctx_t connection_context = {
        .connType = kType_SE_Conn_Type_T1oI2C,
        .portName = SECURE_ELEMENT_I2C_DEVICE,
        .auth.authType = kSSS_AuthType_SCP03,
        .auth.ctx.scp03.pStatic_ctx = &platform_scp_auth_key,
        .auth.ctx.scp03.pDyn_ctx = &platform_scp_session_key,
    };

    int status = sss_session_open(&se_session, kType_SSS_SE_SE05x, 0, 
                                  kSSS_ConnectionType_Encrypted, &connection_context);
    if (status != kStatus_SSS_Success) {
        return -1;
    }

    return 0;
}

int SecureElement_init(void)
{
    axReset_HostConfigure();
    axReset_PowerUp();

    int err = setup_host();
    if (err) {
        return -1;
    }

    err = setup_se();
    if (err) {
        return -2;
    }

    return 0;
}
