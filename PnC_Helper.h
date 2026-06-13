#ifndef PNC_HELPER_H
#define PNC_HELPER_H

#include <stdint.h>
#include <stddef.h>

#include "PnC_Crypto_Port.h"
#include "cbv2g/iso_2/iso2_msgDefDatatypes.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PNC_MAX_V2G_ROOT_CERTS
#define PNC_MAX_V2G_ROOT_CERTS (5u)
#endif

#ifndef PNC_MAX_CONTRACT_CERTS
#define PNC_MAX_CONTRACT_CERTS (1u)
#endif

#ifndef PNC_PCID_SIZE
#define PNC_PCID_SIZE (64u)
#endif

#ifndef PNC_EMAID_SIZE
#define PNC_EMAID_SIZE (iso2_eMAID_CHARACTER_SIZE)
#endif

typedef struct {
    PnC_X509Cert_t cert;
} PnC_Certificate_t;

typedef struct {
    PnC_Certificate_t contract_cert;
} PnC_Contract_t;

typedef struct {
    uint8_t pcid[PNC_PCID_SIZE];
    PnC_Certificate_t oem_pvn;
    PnC_Certificate_t v2g_root[PNC_MAX_V2G_ROOT_CERTS];
    uint8_t len_v2g_root;
    PnC_Contract_t contract[PNC_MAX_CONTRACT_CERTS];
} PnC_Helper_t;

typedef enum {
    PNC_HELPER_OK = 0,
    PNC_HELPER_INVALID_ARG,
    PNC_HELPER_BUFFER_TOO_SMALL,
    PNC_HELPER_CERT_MISSING,
    PNC_HELPER_CERT_CHAIN_INVALID,
    PNC_HELPER_CRYPTO_FAILED,
    PNC_HELPER_STORAGE_FAILED,
} PnC_HelperStatus_t;

typedef struct {
    char characters[PNC_EMAID_SIZE];
    uint16_t charactersLen;
} PnC_EMAID_t;

extern PnC_Helper_t gPnCHelper;
extern PnC_CryptoMethod_t crypto_method_ecdh;
extern PnC_CryptoMethod_t crypto_method_aes_cbc_128;

void PnCHlp_Init(void);
void PnCHlp_CertStoreInit(PnC_Helper_t *helper);
PnC_HelperStatus_t PnCHlp_SetPcid(PnC_Helper_t *helper,
                                  const uint8_t *pcid,
                                  uint16_t pcid_len);
PnC_HelperStatus_t PnCHlp_LoadOemProvisioningCert(PnC_Helper_t *helper,
                                                  uint8_t *cert_der,
                                                  uint16_t cert_der_len,
                                                  uint8_t *raw_buffer,
                                                  uint16_t raw_buffer_len,
                                                  const uint8_t *private_key,
                                                  uint16_t private_key_len,
                                                  UINT private_key_type);
PnC_HelperStatus_t PnCHlp_AddV2GRootCert(PnC_Helper_t *helper,
                                         uint8_t index,
                                         uint8_t *cert_der,
                                         uint16_t cert_der_len,
                                         uint8_t *raw_buffer,
                                         uint16_t raw_buffer_len);
PnC_HelperStatus_t PnCHlp_LoadContractCert(PnC_Helper_t *helper,
                                           uint8_t index,
                                           uint8_t *cert_der,
                                           uint16_t cert_der_len,
                                           uint8_t *raw_buffer,
                                           uint16_t raw_buffer_len,
                                           const uint8_t *private_key,
                                           uint16_t private_key_len,
                                           UINT private_key_type);

UINT PnCHlp_Asn1UtcTimeToUnix(UCHAR *asn1_time, UINT asn1_time_len,
                              UINT asn1_tag, ULONG *unix_time);
UINT PnCHlp_Shared_Secret_Compute(PnC_CryptoMethod_t *method, const uint8_t *peer_public_key,
                                  UINT peer_public_key_len, uint8_t *shared_secret,
                                  UINT shared_secret_size, UINT *shared_secret_actual_len);
UINT PnCHlp_SHA256(const uint8_t *input, UINT input_len, uint8_t output_hash[32]);
UINT PnCHlp_DeCryt_ContractPrivateKey(PnC_CryptoMethod_t *method, const uint8_t aes_key[16],
                                      const uint8_t iv[16], const uint8_t *cipher,
                                      UINT cipher_len, uint8_t *plain_private_key,
                                      uint16_t *plain_private_key_len);
UINT PnCHlp_Contract_Add(const uint8_t *cert, uint16_t cert_len,
                         const uint8_t *private_key, uint16_t private_key_len);
UINT PnCHlp_SubContractCA_Add(const uint8_t *cert, uint16_t cert_len, uint8_t index);
UINT PnCHlp_SAProvisioning_Add(const struct iso2_CertificateChainType *chain);

PnC_HelperStatus_t PnCHlp_BuildCertificateInstallationReq(
    struct iso2_CertificateInstallationReqType *req);

PnC_HelperStatus_t PnCHlp_BuildCertificateUpdateReq(
    struct iso2_CertificateUpdateReqType *req,
    const PnC_EMAID_t *emaid);

PnC_HelperStatus_t PnCHlp_ProcessCertificateInstallationRes(
    const struct iso2_CertificateInstallationResType *res,
    PnC_EMAID_t *emaid_out);

PnC_HelperStatus_t PnCHlp_ProcessCertificateUpdateRes(
    const struct iso2_CertificateUpdateResType *res,
    PnC_EMAID_t *emaid_out);

PnC_HelperStatus_t PnCHlp_ValidateCertificateChain(
    const struct iso2_CertificateChainType *chain);

#ifdef __cplusplus
}
#endif

#endif /* PNC_HELPER_H */
