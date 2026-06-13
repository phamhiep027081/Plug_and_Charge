#include "PnC_Helper.h"

#include <string.h>

#include "cbv2g/common/exi_basetypes.h"
#include "cbv2g/common/exi_error_codes.h"

#ifndef PNC_USE_HSE_CRYPTO
#include "nx_crypto_aes.h"
#include "nx_crypto_ecdh.h"
#include "nx_crypto_sha2.h"

extern NX_CRYPTO_METHOD crypto_method_ec_secp256;
extern NX_CRYPTO_METHOD crypto_method_sha256;
#endif

#define PNC_SECONDS_PER_DAY (86400UL)
#define PNC_CERT_UPDATE_WINDOW_SECONDS (10UL * PNC_SECONDS_PER_DAY)
#define PNC_AES_CBC_IV_SIZE (16u)
#define PNC_AES_128_KEY_SIZE (16u)
#define PNC_SHA256_SIZE (32u)
#define PNC_ECDH_P256_SECRET_SIZE (32u)
#define PNC_CONTRACT_PRIVATE_KEY_BUFFER_SIZE (256u)

#ifdef PNC_USE_HSE_CRYPTO
#define PNC_HELPER_CRYPTO_OK PNC_CRYPTO_SUCCESS
#define PNC_HELPER_X509_OK PNC_X509_SUCCESS
#define PNC_HELPER_X509_KEY_TYPE_NONE PNC_X509_KEY_TYPE_NONE
#else
#define PNC_HELPER_CRYPTO_OK NX_CRYPTO_SUCCESS
#define PNC_HELPER_X509_OK NX_SECURE_X509_SUCCESS
#define PNC_HELPER_X509_KEY_TYPE_NONE NX_SECURE_X509_KEY_TYPE_NONE
#endif

PnC_Helper_t gPnCHelper;

#ifndef PNC_USE_HSE_CRYPTO
static uint8_t g_contract_raw_buffer[PNC_MAX_CONTRACT_CERTS][iso2_certificateType_BYTES_SIZE];
static uint8_t g_contract_private_key_buffer[PNC_MAX_CONTRACT_CERTS][PNC_CONTRACT_PRIVATE_KEY_BUFFER_SIZE];
#endif

#ifndef PNC_USE_HSE_CRYPTO
#define PNC_ALIGNED_METADATA(type, name) \
    ULONG name[((sizeof(type) + sizeof(ULONG) - 1u) / sizeof(ULONG))]
#endif

static PnC_HelperStatus_t copyBoundedBytes(uint8_t *dst, uint16_t dst_size,
                                           const uint8_t *src, ULONG src_len)
{
    if ((dst == NULL) || (src == NULL) || (src_len == 0) || (src_len > dst_size)) {
        return PNC_HELPER_BUFFER_TOO_SMALL;
    }

    memcpy(dst, src, src_len);
    return PNC_HELPER_OK;
}

static PnC_HelperStatus_t copyBoundedString(char *dst, uint16_t dst_size,
                                            const char *src, uint16_t src_len)
{
    if ((dst == NULL) || (src == NULL) || (src_len == 0) || (src_len >= dst_size)) {
        return PNC_HELPER_BUFFER_TOO_SMALL;
    }

    memcpy(dst, src, src_len);
    return PNC_HELPER_OK;
}

static PnC_HelperStatus_t appendDnComponent(char *dst, uint16_t dst_size, uint16_t *offset,
                                            const char *prefix, const UCHAR *value,
                                            uint16_t value_len)
{
    if ((value == NULL) || (value_len == 0)) {
        return PNC_HELPER_OK;
    }

    uint16_t prefix_len = (uint16_t)strlen(prefix);
    uint16_t sep_len = (*offset == 0) ? 0u : 1u;
    if ((*offset + sep_len + prefix_len + value_len) >= dst_size) {
        return PNC_HELPER_BUFFER_TOO_SMALL;
    }

    if (sep_len != 0u) {
        dst[*offset] = ',';
        (*offset)++;
    }

    memcpy(&dst[*offset], prefix, prefix_len);
    *offset += prefix_len;
    memcpy(&dst[*offset], value, value_len);
    *offset += value_len;
    return PNC_HELPER_OK;
}

static PnC_HelperStatus_t fillRootCertificateId(struct iso2_X509IssuerSerialType *cert_id,
                                                const PnC_X509Cert_t *cert)
{
    if ((cert_id == NULL) || (cert == NULL)) {
        return PNC_HELPER_INVALID_ARG;
    }

    const UCHAR *serial = cert->nx_secure_x509_issuer.nx_secure_x509_serial_number;
    uint16_t serial_len = cert->nx_secure_x509_issuer.nx_secure_x509_serial_number_length;
    uint16_t issuer_len = 0;

    init_iso2_X509IssuerSerialType(cert_id);

    if (appendDnComponent(cert_id->X509IssuerName.characters, iso2_X509IssuerName_CHARACTER_SIZE,
                          &issuer_len, "C=", cert->nx_secure_x509_issuer.nx_secure_x509_country,
                          cert->nx_secure_x509_issuer.nx_secure_x509_country_length) != PNC_HELPER_OK) {
        return PNC_HELPER_BUFFER_TOO_SMALL;
    }
    if (appendDnComponent(cert_id->X509IssuerName.characters, iso2_X509IssuerName_CHARACTER_SIZE,
                          &issuer_len, "O=", cert->nx_secure_x509_issuer.nx_secure_x509_organization,
                          cert->nx_secure_x509_issuer.nx_secure_x509_organization_length) != PNC_HELPER_OK) {
        return PNC_HELPER_BUFFER_TOO_SMALL;
    }
    if (appendDnComponent(cert_id->X509IssuerName.characters, iso2_X509IssuerName_CHARACTER_SIZE,
                          &issuer_len, "CN=", cert->nx_secure_x509_issuer.nx_secure_x509_common_name,
                          cert->nx_secure_x509_issuer.nx_secure_x509_common_name_length) != PNC_HELPER_OK) {
        return PNC_HELPER_BUFFER_TOO_SMALL;
    }
    if ((issuer_len == 0u) || (serial == NULL) || (serial_len == 0u)) {
        return PNC_HELPER_CERT_MISSING;
    }

    while ((serial_len > 1u) && (*serial == 0x00u)) {
        serial++;
        serial_len--;
    }

    cert_id->X509IssuerName.charactersLen = issuer_len;
    cert_id->X509SerialNumber.is_negative = 0;
    if (exi_basetypes_convert_bytes_to_unsigned(&cert_id->X509SerialNumber.data,
                                                serial, serial_len) != EXI_ERROR__NO_ERROR) {
        return PNC_HELPER_BUFFER_TOO_SMALL;
    }

    return PNC_HELPER_OK;
}

static PnC_HelperStatus_t fillListOfRootCertificateIds(
    struct iso2_ListOfRootCertificateIDsType *list)
{
    if (list == NULL) {
        return PNC_HELPER_INVALID_ARG;
    }

    uint16_t root_count = gPnCHelper.len_v2g_root;
    init_iso2_ListOfRootCertificateIDsType(list);
    if ((root_count == 0u) || (root_count > iso2_X509IssuerSerialType_5_ARRAY_SIZE)) {
        return PNC_HELPER_CERT_MISSING;
    }

    list->RootCertificateID.arrayLen = root_count;
    for (uint16_t i = 0; i < root_count; i++) {
        PnC_HelperStatus_t status =
            fillRootCertificateId(&list->RootCertificateID.array[i], &gPnCHelper.v2g_root[i].cert);
        if (status != PNC_HELPER_OK) {
            return status;
        }
    }

    return PNC_HELPER_OK;
}

static PnC_HelperStatus_t deriveAesKeyFromDhPublicKey(const uint8_t *dh_public_key,
                                                      uint16_t dh_public_key_len,
                                                      uint8_t aes_key[PNC_AES_128_KEY_SIZE])
{
    uint8_t shared_secret[PNC_ECDH_P256_SECRET_SIZE] = {0};
    UINT shared_secret_actual_len = 0;
    UINT status = PnCHlp_Shared_Secret_Compute(&crypto_method_ecdh, dh_public_key, dh_public_key_len,
                                               shared_secret, sizeof(shared_secret),
                                               &shared_secret_actual_len);
    /* HSE backend:
     * Perform ECDH P-256 inside HSE using a non-exportable ephemeral private key.
     * Only the peer public key from EVSE is input; the private scalar must never
     * be exposed to application RAM.
     */
    if ((status != PNC_HELPER_CRYPTO_OK) || (shared_secret_actual_len != sizeof(shared_secret))) {
        return PNC_HELPER_CRYPTO_FAILED;
    }

    const uint8_t counter[4] = {0x00, 0x00, 0x00, 0x01};
    const uint8_t other_info[3] = {0x01, 0x55, 0x56};
    uint8_t kdf_input[sizeof(counter) + sizeof(shared_secret) + sizeof(other_info)] = {0};
    uint8_t hash[PNC_SHA256_SIZE] = {0};

    memcpy(kdf_input, counter, sizeof(counter));
    memcpy(kdf_input + sizeof(counter), shared_secret, sizeof(shared_secret));
    memcpy(kdf_input + sizeof(counter) + sizeof(shared_secret), other_info, sizeof(other_info));

    /* HSE backend:
     * Run SHA-256/KDF in HSE when available, or keep this software KDF only if
     * shared_secret is allowed to be exported by the target security concept.
     */
    status = PnCHlp_SHA256(kdf_input, sizeof(kdf_input), hash);
    if (status != PNC_HELPER_CRYPTO_OK) {
        return PNC_HELPER_CRYPTO_FAILED;
    }

    memcpy(aes_key, hash, PNC_AES_128_KEY_SIZE);
    return PNC_HELPER_OK;
}

static PnC_HelperStatus_t decryptContractPrivateKey(
    const struct iso2_ContractSignatureEncryptedPrivateKeyType *encrypted_key,
    const struct iso2_DiffieHellmanPublickeyType *dh_public_key,
    uint8_t *plain_private_key,
    uint16_t *plain_private_key_len)
{
    if ((encrypted_key == NULL) || (dh_public_key == NULL) ||
            (plain_private_key == NULL) || (plain_private_key_len == NULL)) {
        return PNC_HELPER_INVALID_ARG;
    }

    uint16_t encrypted_len = encrypted_key->CONTENT.bytesLen;
    if ((dh_public_key->CONTENT.bytesLen == 0u) ||
            (encrypted_len <= PNC_AES_CBC_IV_SIZE) ||
            (((encrypted_len - PNC_AES_CBC_IV_SIZE) % PNC_AES_CBC_IV_SIZE) != 0u)) {
        return PNC_HELPER_CRYPTO_FAILED;
    }

    uint8_t aes_key[PNC_AES_128_KEY_SIZE] = {0};
    PnC_HelperStatus_t status =
        deriveAesKeyFromDhPublicKey(dh_public_key->CONTENT.bytes,
                                    dh_public_key->CONTENT.bytesLen, aes_key);
    if (status != PNC_HELPER_OK) {
        return status;
    }

    const uint8_t *iv = &encrypted_key->CONTENT.bytes[0];
    const uint8_t *cipher = &encrypted_key->CONTENT.bytes[PNC_AES_CBC_IV_SIZE];
    uint16_t cipher_len = encrypted_len - PNC_AES_CBC_IV_SIZE;

    /* HSE backend:
     * AES-128-CBC decrypt should be executed by HSE. The decrypted Contract
     * Signature private key should be imported directly into an HSE key slot as
     * non-exportable instead of being returned in plain_private_key.
     */
    *plain_private_key_len = PNC_CONTRACT_PRIVATE_KEY_BUFFER_SIZE;
    UINT crypto_status = PnCHlp_DeCryt_ContractPrivateKey(&crypto_method_aes_cbc_128,
                                                          aes_key, iv, cipher, cipher_len,
                                                          plain_private_key,
                                                          plain_private_key_len);
    if ((crypto_status != PNC_HELPER_CRYPTO_OK) || (*plain_private_key_len == 0u)) {
        return PNC_HELPER_CRYPTO_FAILED;
    }

    return PNC_HELPER_OK;
}

static PnC_HelperStatus_t storeContractMaterial(
    const struct iso2_CertificateChainType *contract_chain,
    const uint8_t *plain_private_key,
    uint16_t plain_private_key_len)
{
    if ((contract_chain == NULL) || (plain_private_key == NULL) || (plain_private_key_len == 0u)) {
        return PNC_HELPER_INVALID_ARG;
    }

    /* HSE/NVM split:
     * - HSE: Contract Signature private key as a key handle/non-exportable key.
     * - NVM: Contract certificate chain DER, Sub-CA DER and eMAID.
     */
    UINT status = PnCHlp_Contract_Add(contract_chain->Certificate.bytes,
                                      contract_chain->Certificate.bytesLen,
                                      plain_private_key, plain_private_key_len);
    if (status != PNC_HELPER_CRYPTO_OK) {
        return PNC_HELPER_STORAGE_FAILED;
    }

    if (contract_chain->SubCertificates_isUsed) {
        for (uint8_t i = 0; i < contract_chain->SubCertificates.Certificate.arrayLen; i++) {
            status = PnCHlp_SubContractCA_Add(contract_chain->SubCertificates.Certificate.array[i].bytes,
                                             contract_chain->SubCertificates.Certificate.array[i].bytesLen,
                                             i);
            if (status != PNC_HELPER_CRYPTO_OK) {
                return PNC_HELPER_STORAGE_FAILED;
            }
        }
    }

    return PNC_HELPER_OK;
}

static PnC_HelperStatus_t cacheEmaid(const struct iso2_EMAIDType *emaid, PnC_EMAID_t *emaid_out)
{
    if ((emaid == NULL) || (emaid_out == NULL) ||
            (emaid->CONTENT.charactersLen == 0u) ||
            (emaid->CONTENT.charactersLen >= PNC_EMAID_SIZE)) {
        return PNC_HELPER_BUFFER_TOO_SMALL;
    }

    memcpy(emaid_out->characters, emaid->CONTENT.characters, emaid->CONTENT.charactersLen);
    emaid_out->charactersLen = emaid->CONTENT.charactersLen;
    return PNC_HELPER_OK;
}

static PnC_HelperStatus_t initNetXDuoCert(PnC_Certificate_t *slot,
                                          uint8_t *cert_der,
                                          uint16_t cert_der_len,
                                          uint8_t *raw_buffer,
                                          uint16_t raw_buffer_len,
                                          const uint8_t *private_key,
                                          uint16_t private_key_len,
                                          UINT private_key_type)
{
    if ((slot == NULL) || (cert_der == NULL) || (cert_der_len == 0u)) {
        return PNC_HELPER_INVALID_ARG;
    }

    memset(slot, 0, sizeof(*slot));
    /* NetX backend parses the cert and keeps the optional software private key.
     * HSE backend should parse/import public cert metadata but store private_key
     * as an HSE key handle only. Public DER remains suitable for NVM storage.
     */
#ifdef PNC_USE_HSE_CRYPTO
    UINT status = PnCHse_X509CertificateImport(&slot->cert,
                                               cert_der,
                                               cert_der_len,
                                               raw_buffer,
                                               raw_buffer_len,
                                               private_key,
                                               private_key_len,
                                               private_key_type);
#else
    UINT status = nx_secure_x509_certificate_initialize(&slot->cert,
                                                        cert_der,
                                                        cert_der_len,
                                                        raw_buffer,
                                                        raw_buffer_len,
                                                        private_key,
                                                        private_key_len,
                                                        private_key_type);
#endif
    return (status == PNC_HELPER_X509_OK) ? PNC_HELPER_OK : PNC_HELPER_CERT_CHAIN_INVALID;
}

void PnCHlp_CertStoreInit(PnC_Helper_t *helper)
{
    if (helper != NULL) {
        memset(helper, 0, sizeof(*helper));
    }
}

void PnCHlp_Init(void)
{
    PnCHlp_CertStoreInit(&gPnCHelper);
}

#ifndef PNC_USE_HSE_CRYPTO
static const NX_SECURE_EC_PRIVATE_KEY *getActiveEcPrivateKey(void)
{
    const NX_SECURE_EC_PRIVATE_KEY *contract_key =
        &gPnCHelper.contract[0].contract_cert.cert.nx_secure_x509_private_key.ec_private_key;
    const NX_SECURE_EC_PRIVATE_KEY *oem_key =
        &gPnCHelper.oem_pvn.cert.nx_secure_x509_private_key.ec_private_key;

    if ((contract_key->nx_secure_ec_private_key != NULL) &&
            (contract_key->nx_secure_ec_private_key_length != 0u)) {
        return contract_key;
    }

    if ((oem_key->nx_secure_ec_private_key != NULL) &&
            (oem_key->nx_secure_ec_private_key_length != 0u)) {
        return oem_key;
    }

    return NULL;
}

UINT PnCHlp_Shared_Secret_Compute(PnC_CryptoMethod_t *method,
                                  const uint8_t *peer_public_key,
                                  UINT peer_public_key_len,
                                  uint8_t *shared_secret,
                                  UINT shared_secret_size,
                                  UINT *shared_secret_actual_len)
{
    if ((method == NULL) || (method->nx_crypto_operation == NULL) ||
            (peer_public_key == NULL) || (peer_public_key_len == 0u) ||
            (shared_secret == NULL) || (shared_secret_actual_len == NULL)) {
        return NX_CRYPTO_PTR_ERROR;
    }

    const NX_SECURE_EC_PRIVATE_KEY *private_key = getActiveEcPrivateKey();
    if (private_key == NULL) {
        return NX_CRYPTO_PTR_ERROR;
    }

    VOID *handler = NULL;
    PNC_ALIGNED_METADATA(NX_CRYPTO_ECDH, ecdh_metadata);
    NX_CRYPTO_EXTENDED_OUTPUT extended_output;
    UINT status;

    memset(ecdh_metadata, 0, sizeof(ecdh_metadata));
    if (method->nx_crypto_init != NULL) {
        status = method->nx_crypto_init(method, NULL, 0u, &handler,
                                        ecdh_metadata, sizeof(ecdh_metadata));
        if (status != NX_CRYPTO_SUCCESS) {
            return status;
        }
    }

    status = method->nx_crypto_operation(NX_CRYPTO_EC_CURVE_SET, handler,
                                         method, NULL, 0u,
                                         (UCHAR *)&crypto_method_ec_secp256,
                                         sizeof(NX_CRYPTO_METHOD *),
                                         NULL, NULL, 0u,
                                         ecdh_metadata, sizeof(ecdh_metadata),
                                         NULL, NULL);
    if (status == NX_CRYPTO_SUCCESS) {
        status = method->nx_crypto_operation(NX_CRYPTO_DH_KEY_PAIR_IMPORT, handler,
                                             method,
                                             (UCHAR *)private_key->nx_secure_ec_private_key,
                                             (NX_CRYPTO_KEY_SIZE)(private_key->nx_secure_ec_private_key_length << 3),
                                             NULL, 0u,
                                             NULL, NULL, 0u,
                                             ecdh_metadata, sizeof(ecdh_metadata),
                                             NULL, NULL);
    }

    if (status == NX_CRYPTO_SUCCESS) {
        memset(&extended_output, 0, sizeof(extended_output));
        extended_output.nx_crypto_extended_output_data = shared_secret;
        extended_output.nx_crypto_extended_output_length_in_byte = shared_secret_size;
        status = method->nx_crypto_operation(NX_CRYPTO_DH_CALCULATE, handler,
                                             method, NULL, 0u,
                                             (UCHAR *)peer_public_key,
                                             peer_public_key_len,
                                             NULL,
                                             (UCHAR *)&extended_output,
                                             sizeof(extended_output),
                                             ecdh_metadata, sizeof(ecdh_metadata),
                                             NULL, NULL);
        *shared_secret_actual_len = (UINT)extended_output.nx_crypto_extended_output_actual_size;
    }

    if (method->nx_crypto_cleanup != NULL) {
        (void)method->nx_crypto_cleanup(ecdh_metadata);
    }

    return status;
}

UINT PnCHlp_SHA256(const uint8_t *input, UINT input_len, uint8_t output_hash[32])
{
    if ((input == NULL) || (input_len == 0u) || (output_hash == NULL) ||
            (crypto_method_sha256.nx_crypto_operation == NULL)) {
        return NX_CRYPTO_PTR_ERROR;
    }

    PNC_ALIGNED_METADATA(NX_CRYPTO_SHA256, sha256_metadata);
    memset(sha256_metadata, 0, sizeof(sha256_metadata));

    return crypto_method_sha256.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                    NULL,
                                                    &crypto_method_sha256,
                                                    NULL,
                                                    0u,
                                                    (UCHAR *)input,
                                                    input_len,
                                                    NULL,
                                                    output_hash,
                                                    PNC_SHA256_SIZE,
                                                    sha256_metadata,
                                                    sizeof(sha256_metadata),
                                                    NULL,
                                                    NULL);
}

UINT PnCHlp_DeCryt_ContractPrivateKey(PnC_CryptoMethod_t *method,
                                      const uint8_t aes_key[PNC_AES_128_KEY_SIZE],
                                      const uint8_t iv[PNC_AES_CBC_IV_SIZE],
                                      const uint8_t *cipher,
                                      UINT cipher_len,
                                      uint8_t *plain_private_key,
                                      uint16_t *plain_private_key_len)
{
    if ((method == NULL) || (method->nx_crypto_operation == NULL) ||
            (aes_key == NULL) || (iv == NULL) || (cipher == NULL) ||
            (cipher_len == 0u) || (plain_private_key == NULL) ||
            (plain_private_key_len == NULL)) {
        return NX_CRYPTO_PTR_ERROR;
    }

    VOID *handler = NULL;
    PNC_ALIGNED_METADATA(NX_CRYPTO_AES, aes_metadata);
    UINT status;

    memset(aes_metadata, 0, sizeof(aes_metadata));
    if (method->nx_crypto_init != NULL) {
        status = method->nx_crypto_init(method,
                                        (UCHAR *)aes_key,
                                        NX_CRYPTO_AES_128_KEY_LEN_IN_BITS,
                                        &handler,
                                        aes_metadata,
                                        sizeof(aes_metadata));
        if (status != NX_CRYPTO_SUCCESS) {
            return status;
        }
    }

    status = method->nx_crypto_operation(NX_CRYPTO_DECRYPT,
                                         handler,
                                         method,
                                         (UCHAR *)aes_key,
                                         NX_CRYPTO_AES_128_KEY_LEN_IN_BITS,
                                         (UCHAR *)cipher,
                                         cipher_len,
                                         (UCHAR *)iv,
                                         plain_private_key,
                                         *plain_private_key_len,
                                         aes_metadata,
                                         sizeof(aes_metadata),
                                         NULL,
                                         NULL);
    if (status == NX_CRYPTO_SUCCESS) {
        uint16_t actual_len = (uint16_t)cipher_len;
        if (actual_len != 0u) {
            uint8_t padding_len = plain_private_key[actual_len - 1u];
            if ((padding_len > 0u) && (padding_len <= PNC_AES_CBC_IV_SIZE) &&
                    (padding_len <= actual_len)) {
                actual_len = (uint16_t)(actual_len - padding_len);
            }
        }
        *plain_private_key_len = actual_len;
    }

    if (method->nx_crypto_cleanup != NULL) {
        (void)method->nx_crypto_cleanup(aes_metadata);
    }

    return status;
}

UINT PnCHlp_Asn1UtcTimeToUnix(UCHAR *asn1_time, UINT asn1_time_len,
                              UINT asn1_tag, ULONG *unix_time)
{
    static const UINT days_before_month[12] =
        {0u, 31u, 59u, 90u, 120u, 151u, 181u, 212u, 243u, 273u, 304u, 334u};

    if ((asn1_time == NULL) || (unix_time == NULL) ||
            (asn1_tag != NX_SECURE_ASN_TAG_UTC_TIME) || (asn1_time_len < 11u)) {
        return NX_SECURE_X509_INVALID_DATE_FORMAT;
    }

    long year = (long)(((asn1_time[0] - '0') * 10) + (asn1_time[1] - '0'));
    long month = (long)(((asn1_time[2] - '0') * 10) + (asn1_time[3] - '0'));
    long day = (long)(((asn1_time[4] - '0') * 10) + (asn1_time[5] - '0')) - 1L;
    long hour = (long)(((asn1_time[6] - '0') * 10) + (asn1_time[7] - '0'));
    long minute = (long)(((asn1_time[8] - '0') * 10) + (asn1_time[9] - '0'));
    long second = 0;
    UINT index = 10u;

    if ((month < 1L) || (month > 12L) || (day < 0L) || (day > 30L) ||
            (hour > 23L) || (minute > 59L)) {
        return NX_SECURE_X509_INVALID_DATE_FORMAT;
    }

    if ((index + 1u < asn1_time_len) &&
            (asn1_time[index] != 'Z') &&
            (asn1_time[index] != '+') &&
            (asn1_time[index] != '-')) {
        second = (LONG)(((asn1_time[index] - '0') * 10) + (asn1_time[index + 1u] - '0'));
        index += 2u;
    }

    if (second > 59L) {
        return NX_SECURE_X509_INVALID_DATE_FORMAT;
    }

    if (index >= asn1_time_len) {
        return NX_SECURE_X509_INVALID_DATE_FORMAT;
    }

    if (asn1_time[index] != 'Z') {
        if ((index + 4u) >= asn1_time_len) {
            return NX_SECURE_X509_INVALID_DATE_FORMAT;
        }

        long offset_hour = (long)(((asn1_time[index + 1u] - '0') * 10) + (asn1_time[index + 2u] - '0'));
        long offset_minute = (long)(((asn1_time[index + 3u] - '0') * 10) + (asn1_time[index + 4u] - '0'));
        if (asn1_time[index] == '+') {
            hour -= offset_hour;
            minute -= offset_minute;
        } else if (asn1_time[index] == '-') {
            hour += offset_hour;
            minute += offset_minute;
        } else {
            return NX_SECURE_X509_INVALID_DATE_FORMAT;
        }
    }

    if (year >= 70L) {
        year -= 70L;
        if (year >= 2L) {
            day += ((year + 2L) / 4L) + 1L;
        }
    } else {
        year += 30L;
        day += ((year - 2L) / 4L) + 1L;
    }

    day += year * 365L;
    day += (long)days_before_month[month - 1L];
    hour += day * 24L;
    minute += hour * 60L;
    second += minute * 60L;
    *unix_time = (ULONG)second;

    return NX_SECURE_X509_SUCCESS;
}

UINT PnCHlp_Contract_Add(const uint8_t *cert, uint16_t cert_len,
                         const uint8_t *private_key, uint16_t private_key_len)
{
    if ((cert == NULL) || (cert_len == 0u) ||
            (private_key == NULL) || (private_key_len == 0u)) {
        return NX_CRYPTO_PTR_ERROR;
    }
    if (private_key_len > sizeof(g_contract_private_key_buffer[0])) {
        return NX_CRYPTO_SIZE_ERROR;
    }

    memcpy(g_contract_private_key_buffer[0], private_key, private_key_len);

    PnC_HelperStatus_t status = PnCHlp_LoadContractCert(&gPnCHelper,
                                                        0u,
                                                        (uint8_t *)cert,
                                                        cert_len,
                                                        g_contract_raw_buffer[0],
                                                        sizeof(g_contract_raw_buffer[0]),
                                                        g_contract_private_key_buffer[0],
                                                        private_key_len,
                                                        NX_SECURE_X509_KEY_TYPE_EC_DER);
    return (status == PNC_HELPER_OK) ? NX_CRYPTO_SUCCESS : NX_CRYPTO_NOT_SUCCESSFUL;
}

UINT PnCHlp_SubContractCA_Add(const uint8_t *cert, uint16_t cert_len, uint8_t index)
{
    (void)index;
    if ((cert == NULL) || (cert_len == 0u)) {
        return NX_CRYPTO_PTR_ERROR;
    }

    /* Project storage hook: NetX Secure parses identity/trust anchors, but this
     * helper still needs the platform NVM module to persist MO Sub-CA chains.
     */
    return NX_CRYPTO_SUCCESS;
}
#endif /* PNC_USE_HSE_CRYPTO */

UINT PnCHlp_SAProvisioning_Add(const struct iso2_CertificateChainType *chain)
{
    (void)chain;
    /* NVM: SAProvisioning certificate chain is public trust material. Store it
     * with integrity protection/rollback protection where available.
     */
    return PNC_HELPER_CRYPTO_OK;
}

PnC_HelperStatus_t PnCHlp_SetPcid(PnC_Helper_t *helper,
                                  const uint8_t *pcid,
                                  uint16_t pcid_len)
{
    if ((helper == NULL) || (pcid == NULL) || (pcid_len == 0u) || (pcid_len >= PNC_PCID_SIZE)) {
        return PNC_HELPER_BUFFER_TOO_SMALL;
    }

    memset(helper->pcid, 0, sizeof(helper->pcid));
    memcpy(helper->pcid, pcid, pcid_len);
    return PNC_HELPER_OK;
}

PnC_HelperStatus_t PnCHlp_LoadOemProvisioningCert(PnC_Helper_t *helper,
                                                  uint8_t *cert_der,
                                                  uint16_t cert_der_len,
                                                  uint8_t *raw_buffer,
                                                  uint16_t raw_buffer_len,
                                                  const uint8_t *private_key,
                                                  uint16_t private_key_len,
                                                  UINT private_key_type)
{
    if (helper == NULL) {
        return PNC_HELPER_INVALID_ARG;
    }

    return initNetXDuoCert(&helper->oem_pvn, cert_der, cert_der_len,
                           raw_buffer, raw_buffer_len,
                           private_key, private_key_len, private_key_type);
}

PnC_HelperStatus_t PnCHlp_AddV2GRootCert(PnC_Helper_t *helper,
                                         uint8_t index,
                                         uint8_t *cert_der,
                                         uint16_t cert_der_len,
                                         uint8_t *raw_buffer,
                                         uint16_t raw_buffer_len)
{
    if ((helper == NULL) || (index >= PNC_MAX_V2G_ROOT_CERTS)) {
        return PNC_HELPER_INVALID_ARG;
    }

    PnC_HelperStatus_t status = initNetXDuoCert(&helper->v2g_root[index],
                                                cert_der, cert_der_len,
                                                raw_buffer, raw_buffer_len,
                                                NULL, 0, PNC_HELPER_X509_KEY_TYPE_NONE);
    if ((status == PNC_HELPER_OK) && (helper->len_v2g_root <= index)) {
        helper->len_v2g_root = (uint8_t)(index + 1u);
    }

    return status;
}

PnC_HelperStatus_t PnCHlp_LoadContractCert(PnC_Helper_t *helper,
                                           uint8_t index,
                                           uint8_t *cert_der,
                                           uint16_t cert_der_len,
                                           uint8_t *raw_buffer,
                                           uint16_t raw_buffer_len,
                                           const uint8_t *private_key,
                                           uint16_t private_key_len,
                                           UINT private_key_type)
{
    if ((helper == NULL) || (index >= PNC_MAX_CONTRACT_CERTS)) {
        return PNC_HELPER_INVALID_ARG;
    }

    return initNetXDuoCert(&helper->contract[index].contract_cert,
                           cert_der, cert_der_len,
                           raw_buffer, raw_buffer_len,
                           private_key, private_key_len, private_key_type);
}

PnC_HelperStatus_t PnCHlp_ValidateCertificateChain(const struct iso2_CertificateChainType *chain)
{
    if (chain == NULL) {
        return PNC_HELPER_INVALID_ARG;
    }
    if ((chain->Certificate.bytesLen == 0u) ||
            (chain->Certificate.bytesLen > iso2_certificateType_BYTES_SIZE)) {
        return PNC_HELPER_CERT_CHAIN_INVALID;
    }
    if (chain->SubCertificates_isUsed &&
            (chain->SubCertificates.Certificate.arrayLen > iso2_certificateType_4_ARRAY_SIZE)) {
        return PNC_HELPER_CERT_CHAIN_INVALID;
    }
    if (chain->SubCertificates_isUsed) {
        for (uint16_t i = 0; i < chain->SubCertificates.Certificate.arrayLen; i++) {
            uint16_t cert_len = chain->SubCertificates.Certificate.array[i].bytesLen;
            if ((cert_len == 0u) || (cert_len > iso2_certificateType_BYTES_SIZE)) {
                return PNC_HELPER_CERT_CHAIN_INVALID;
            }
        }
    }

    return PNC_HELPER_OK;
}

PnC_HelperStatus_t PnCHlp_BuildCertificateInstallationReq(
    struct iso2_CertificateInstallationReqType *req)
{
    if (req == NULL) {
        return PNC_HELPER_INVALID_ARG;
    }

    /* ISO 15118-2 CertificateInstallationReq is used when the EV selected
     * Plug & Charge but has no usable Contract Certificate yet, or the stored
     * Contract Certificate is already expired. The request carries the OEM
     * Provisioning Certificate so the backend/PKI can authenticate the vehicle
     * provisioning identity and issue a new MO/Contract certificate set.
     */
    init_iso2_CertificateInstallationReqType(req);

    /* Step 1: Id.
     * This ID is the XML element identifier used by XML Signature references.
     * It must be stable inside this message and should be signed later together
     * with the message body by the OEM provisioning credential.
     */
    uint16_t pcid_len = (uint16_t)strlen((const char *)gPnCHelper.pcid);
    PnC_HelperStatus_t status = copyBoundedString(req->Id.characters, iso2_Id_CHARACTER_SIZE,
                                                  (const char *)gPnCHelper.pcid, pcid_len);
    if (status != PNC_HELPER_OK) {
        return status;
    }
    req->Id.charactersLen = pcid_len;

    /* Step 2: OEMProvisioningCert.
     * Public DER certificate stored in NVM. Its private key must be held by HSE
     * or NetX Secure key material and used only for the XMLDSig/ECDSA signature.
     */
    status = copyBoundedBytes(req->OEMProvisioningCert.bytes, iso2_certificateType_BYTES_SIZE,
                              gPnCHelper.oem_pvn.cert.nx_secure_x509_certificate_data,
                              gPnCHelper.oem_pvn.cert.nx_secure_x509_certificate_data_length);
    if (status != PNC_HELPER_OK) {
        return status;
    }
    req->OEMProvisioningCert.bytesLen =
        (uint16_t)gPnCHelper.oem_pvn.cert.nx_secure_x509_certificate_data_length;

    /* Step 3: ListOfRootCertificateIDs.
     * EV tells EVSE/backend which V2G Root CA trust anchors it supports so the
     * returned ContractSignatureCertChain can be built to a trusted root.
     */
    return fillListOfRootCertificateIds(&req->ListOfRootCertificateIDs);
}

PnC_HelperStatus_t PnCHlp_BuildCertificateUpdateReq(
    struct iso2_CertificateUpdateReqType *req,
    const PnC_EMAID_t *emaid)
{
    if ((req == NULL) || (emaid == NULL)) {
        return PNC_HELPER_INVALID_ARG;
    }

    /* ISO 15118-2 CertificateUpdateReq is used only when the current Contract
     * Certificate is still valid but inside the configured renewal window. If
     * it is expired, use CertificateInstallationReq because the expired contract
     * credential can no longer be relied on for normal PnC authorization.
     */
    init_iso2_CertificateUpdateReqType(req);

    /* Step 1: Id.
     * This message ID is used by XML Signature references. The update request
     * must be signed with the current valid Contract Signature private key.
     */
    uint16_t pcid_len = (uint16_t)strlen((const char *)gPnCHelper.pcid);
    PnC_HelperStatus_t status = copyBoundedString(req->Id.characters, iso2_Id_CHARACTER_SIZE,
                                                  (const char *)gPnCHelper.pcid, pcid_len);
    if (status != PNC_HELPER_OK) {
        return status;
    }
    req->Id.charactersLen = pcid_len;

    /* Step 2: ContractSignatureCertChain.
     * Send the currently installed Contract Certificate chain. The backend uses
     * it to identify the eMSP contract that must be renewed/reissued.
     */
    ULONG contract_cert_len =
        gPnCHelper.contract[0].contract_cert.cert.nx_secure_x509_certificate_data_length;
    req->ContractSignatureCertChain.Id_isUsed = 0u;
    req->ContractSignatureCertChain.SubCertificates_isUsed = 0u;
    status = copyBoundedBytes(req->ContractSignatureCertChain.Certificate.bytes,
                              iso2_certificateType_BYTES_SIZE,
                              gPnCHelper.contract[0].contract_cert.cert.nx_secure_x509_certificate_data,
                              contract_cert_len);
    if (status != PNC_HELPER_OK) {
        return status;
    }
    req->ContractSignatureCertChain.Certificate.bytesLen = (uint16_t)contract_cert_len;

    /* Step 3: eMAID.
     * e-Mobility Account Identifier links the vehicle contract to the eMSP
     * account and must match the currently stored contract material.
     */
    status = copyBoundedString(req->eMAID.characters, iso2_eMAID_CHARACTER_SIZE,
                               emaid->characters, emaid->charactersLen);
    if (status != PNC_HELPER_OK) {
        return status;
    }
    req->eMAID.charactersLen = emaid->charactersLen;

    /* Step 4: ListOfRootCertificateIDs.
     * Same purpose as installation: advertise accepted V2G Root CA anchors for
     * the new ContractSignatureCertChain returned by the backend.
     */
    return fillListOfRootCertificateIds(&req->ListOfRootCertificateIDs);
}

PnC_HelperStatus_t PnCHlp_ProcessCertificateInstallationRes(
    const struct iso2_CertificateInstallationResType *res,
    PnC_EMAID_t *emaid_out)
{
    if ((res == NULL) || (emaid_out == NULL)) {
        return PNC_HELPER_INVALID_ARG;
    }

    /* Step 1: Validate response certificate payloads before touching storage.
     * SAProvisioningCertificateChain is stored for future provisioning/update
     * context. ContractSignatureCertChain contains the new Contract Certificate
     * plus optional MO Sub-CA certificates that chain to a V2G Root CA.
     */
    PnC_HelperStatus_t status = PnCHlp_ValidateCertificateChain(&res->SAProvisioningCertificateChain);
    if (status != PNC_HELPER_OK) {
        return status;
    }
    status = PnCHlp_ValidateCertificateChain(&res->ContractSignatureCertChain);
    if (status != PNC_HELPER_OK) {
        return status;
    }

    /* Step 2: Decrypt ContractSignatureEncryptedPrivateKey.
     * ISO 15118-2 uses EVSE DHpublickey + EV private ECDH key to derive Z, then
     * SHA-256 KDF to AES-128 key, then AES-CBC decrypt. For HSE, ECDH/AES and
     * private-key import should stay inside HSE so plaintext key bytes are not
     * exposed to application RAM.
     */
    uint8_t plain_private_key[PNC_CONTRACT_PRIVATE_KEY_BUFFER_SIZE] = {0};
    uint16_t plain_private_key_len = 0;
    status = decryptContractPrivateKey(&res->ContractSignatureEncryptedPrivateKey,
                                       &res->DHpublickey,
                                       plain_private_key,
                                       &plain_private_key_len);
    if (status != PNC_HELPER_OK) {
        return status;
    }

    /* Step 3: Store new contract material.
     * HSE: Contract Signature private key as non-exportable key handle.
     * NVM: Contract Certificate DER, MO Sub-CA DER, SAProvisioning chain, eMAID.
     */
    status = storeContractMaterial(&res->ContractSignatureCertChain,
                                   plain_private_key,
                                   plain_private_key_len);
    if (status != PNC_HELPER_OK) {
        return status;
    }

    /* Step 4: Persist SA provisioning chain and cache eMAID.
     * eMAID is needed immediately for PaymentDetailsReq and later CertificateUpdateReq.
     */
    (void)PnCHlp_SAProvisioning_Add(&res->SAProvisioningCertificateChain);
    return cacheEmaid(&res->eMAID, emaid_out);
}

PnC_HelperStatus_t PnCHlp_ProcessCertificateUpdateRes(
    const struct iso2_CertificateUpdateResType *res,
    PnC_EMAID_t *emaid_out)
{
    if ((res == NULL) || (emaid_out == NULL)) {
        return PNC_HELPER_INVALID_ARG;
    }

    /* Step 1: Validate update response chains before replacing current contract.
     * The update response has the same important material as installation, plus
     * optional RetryCounter for backend retry policy when relevant.
     */
    PnC_HelperStatus_t status = PnCHlp_ValidateCertificateChain(&res->SAProvisioningCertificateChain);
    if (status != PNC_HELPER_OK) {
        return status;
    }
    status = PnCHlp_ValidateCertificateChain(&res->ContractSignatureCertChain);
    if (status != PNC_HELPER_OK) {
        return status;
    }

    /* Step 2: Decrypt the updated Contract Signature private key with the same
     * ECDH/KDF/AES-CBC procedure used by installation.
     */
    uint8_t plain_private_key[PNC_CONTRACT_PRIVATE_KEY_BUFFER_SIZE] = {0};
    uint16_t plain_private_key_len = 0;
    status = decryptContractPrivateKey(&res->ContractSignatureEncryptedPrivateKey,
                                       &res->DHpublickey,
                                       plain_private_key,
                                       &plain_private_key_len);
    if (status != PNC_HELPER_OK) {
        return status;
    }

    /* Step 3: Atomically replace the stored contract material.
     * Production storage should write new NVM entries first, verify them, then
     * switch the active slot to avoid losing the old still-valid certificate on
     * power loss. The HSE key slot should be updated with rollback protection.
     */
    status = storeContractMaterial(&res->ContractSignatureCertChain,
                                   plain_private_key,
                                   plain_private_key_len);
    if (status != PNC_HELPER_OK) {
        return status;
    }

    /* Step 4: Persist SA provisioning chain and updated eMAID. If RetryCounter is
     * present, store it in NVM/audit state for backend retry/backoff handling.
     */
    (void)PnCHlp_SAProvisioning_Add(&res->SAProvisioningCertificateChain);
    return cacheEmaid(&res->eMAID, emaid_out);
}
