#ifndef PNC_CRYPTO_PORT_H
#define PNC_CRYPTO_PORT_H

#include <stdint.h>

/* Select the PnC crypto backend.
 *
 * Default: NetX Secure software crypto/X.509 parser.
 * HSE: define PNC_USE_HSE_CRYPTO when the target uses a Hardware Security Engine
 *      for AES-128/192/256, RSA, ECC, secure boot, side-channel protected key
 *      operations and hardware-backed key storage.
 *
 * PnC data placement guideline:
 * - HSE secure key store:
 *   - OEM provisioning private key, if provisioned on the EV.
 *   - Contract Signature private key decrypted from CertificateInstallationRes/
 *     CertificateUpdateRes. Store/import as a non-exportable HSE ECC key handle.
 *   - TLS client private key, if mutual TLS is used by the platform.
 *   - Ephemeral ECDH private key and derived AES key should stay inside HSE RAM/key
 *     slots and be zeroized immediately after use.
 *   - XMLDSig/ECDSA signing keys and any RSA/ECC verification accelerators.
 * - NVM/Flash outside HSE, integrity protected if possible:
 *   - Contract certificate chain DER bytes, Sub-CA certificates and SAProvisioning
 *     certificate chain.
 *   - V2G root CA certificates/trust anchors. Prefer authenticated/secure boot
 *     protected storage because a modified trust anchor breaks PnC security.
 *   - OEM provisioning certificate DER bytes. The public certificate can be in NVM;
 *     only its private key belongs in HSE.
 *   - eMAID, PCID, certificate validity metadata/notAfter Unix time, selected
 *     service/authorization state needed to resume a session.
 *   - Retry counters, update-window policy and audit/error status.
 */

#ifndef PNC_USE_HSE_CRYPTO

#include "nx_crypto.h"
#include "nx_secure_x509.h"

typedef NX_CRYPTO_METHOD PnC_CryptoMethod_t;
typedef NX_SECURE_X509_CERT PnC_X509Cert_t;

#else /* PNC_USE_HSE_CRYPTO */

typedef unsigned int UINT;
typedef unsigned long ULONG;
typedef unsigned char UCHAR;
typedef unsigned short USHORT;

#define PNC_CRYPTO_SUCCESS 0u
#define PNC_X509_SUCCESS 0u
#define PNC_X509_KEY_TYPE_NONE 0u
#define PNC_X509_CERTIFICATE_EXPIRED 1u
#define PNC_ASN_TAG_UTC_TIME 0x17u

typedef uint32_t PnC_HseKeyHandle_t;

typedef struct {
    UCHAR *nx_secure_x509_country;
    USHORT nx_secure_x509_country_length;
    UCHAR *nx_secure_x509_organization;
    USHORT nx_secure_x509_organization_length;
    UCHAR *nx_secure_x509_common_name;
    USHORT nx_secure_x509_common_name_length;
    UCHAR *nx_secure_x509_serial_number;
    USHORT nx_secure_x509_serial_number_length;
} PnC_HseX509Issuer_t;

typedef struct {
    UCHAR *nx_secure_ec_private_key;
    USHORT nx_secure_ec_private_key_length;
    PnC_HseKeyHandle_t hse_key_handle;
} PnC_HseEcPrivateKey_t;

typedef struct {
    PnC_HseEcPrivateKey_t ec_private_key;
} PnC_HsePrivateKey_t;

typedef struct {
    UCHAR *nx_secure_x509_certificate_data;
    ULONG nx_secure_x509_certificate_data_length;
    PnC_HseX509Issuer_t nx_secure_x509_issuer;
    PnC_HsePrivateKey_t nx_secure_x509_private_key;
    UINT nx_secure_x509_private_key_type;
    ULONG nx_secure_x509_not_after;
} PnC_X509Cert_t;

typedef struct {
    UINT algorithm;
    UINT key_size_bits;
    PnC_HseKeyHandle_t hse_key_handle;
} PnC_CryptoMethod_t;

#ifdef __cplusplus
extern "C" {
#endif
UINT PnCHse_X509CertificateImport(PnC_X509Cert_t *certificate,
                                  UCHAR *certificate_data,
                                  USHORT length,
                                  UCHAR *raw_data_buffer,
                                  USHORT raw_data_buffer_size,
                                  const UCHAR *private_key,
                                  USHORT private_key_length,
                                  UINT private_key_type);
UINT PnCHse_X509ExpirationCheck(PnC_X509Cert_t *certificate, ULONG unix_time);
#ifdef __cplusplus
}
#endif

#endif /* PNC_USE_HSE_CRYPTO */

#endif /* PNC_CRYPTO_PORT_H */
