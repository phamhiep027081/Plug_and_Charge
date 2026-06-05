#include "cbv2g/app_handshake/appHand_Decoder.h"
#include "cbv2g/app_handshake/appHand_Encoder.h"
#include "cbv2g/iso_2/iso2_msgDefEncoder.h"
#include "cbv2g/iso_2/iso2_msgDefDecoder.h"
#include "cbv2g/din/din_msgDefDecoder.h"
#include "cbv2g/din/din_msgDefEncoder.h"
#include "cbv2g/exi_v2gtp.h"
#include "cbv2g/common/exi_basetypes.h"
#include "cbv2g/common/exi_error_codes.h"
#include "Iso15118_2.h"
#include "ChrgM.h"
#include "ChrgM_Helper.hpp"
 
// #ifndef VF_USE_NX_SECURE
// #define VF_USE_NX_SECURE
// #endif
 
#ifdef VF_USE_NX_SECURE
#include "PnC_Helper.h"
#include "base64.h"
#endif
#include <math.h>
#include <string.h>
#include "Dio_Cfg.h"
#include "Dio.h"
#include "SwAdapt.h"
#include "Rte_IoHwAb_Lib.h"
//#include "Rte_DcmDIdMgr.h"
 
#ifdef __cplusplus
extern "C"
{
#endif
 
#include "SoAd.h"
#include "SoAd_Cfg.h"
#include "EVCCSlac.h"
#include "EthIf.h"
 
#ifdef __cplusplus
}
#endif
 
#define CHRGM_PERIOD (10)
 
#ifdef VF_USE_NX_SECURE
#define IS_SECURE (1)
extern PnC_Helper_t gPnCHelper;
/* These NetX crypto methods currently use the configured software crypto backend.
 * They are the main replacement points for a hardware crypto driver/HSM:
 * - ECDH P-256 shared-secret calculation
 * - AES-128-CBC contract private-key decryption
 */
extern NX_CRYPTO_METHOD crypto_method_ecdh;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_128;
#else
#define IS_SECURE (0)
#endif
 
#define SDP_SECC_IP_OFFSET (0)
#define SDP_SECC_PORT_OFFSET (16u)
#define SDP_SECC_SECURITY_OFFSET (18u)
#define SDP_SECC_PROTOCOL_OFFSET (19u)
 
ChrgM_StatusType ChrgM_Status;
ChrgM_InputType ChrgM_Input;
ChrgM_OutputType ChrgM_Output;
 
#define V2G_UDP_SERVER_PORT (15118)

static boolean _isTlsConnection(void)
{
    return (ChrgM_Status.seccSecurity == 0x00);
}
 
#define DEF_INIT_MSG(msg)                                                                                       \
    void init_##msg(struct iso2_##msg *doc) { init_iso2_##msg(doc); } \
    void init_##msg(struct din_##msg *doc) { init_din_##msg(doc); }
 
#define SEND_REQ_MSG(msg)                                           \
    if (ChrgM_Output.protocol == ISO15118_2)    \
    {                                                                                       \
        send##msg(&ChrgM_Status.exiDoc.iso2);           \
    }                                                                                       \
    else if (ChrgM_Output.protocol == DIN70121) \
    {                                                                                       \
        send##msg(&ChrgM_Status.exiDoc.din);            \
    }
 
static uint16 _setTimer(uint16 time) { return time / CHRGM_PERIOD; }
 
void ChrgM_Init(void)
{
    ChrgM_Status.state = ChrgM_Idle;
    ChrgM_Status.shutdownTimer = 0xFFFF;
    ChrgM_Output.stEvseNotif = 0;
    ChrgM_Output.stEvseChMode = 0xFF;
    ChrgM_Status.SAScheduleID = 0;
    ChrgM_Status.stReadySlac = 0;
    ChrgM_Status.wakeFirstCheck = false;
    ChrgM_Status.dataField = PROTOCOL_VER;
    ChrgM_Status.offset = 0;
    ChrgM_Status.triggerStop = false;
    ChrgM_Status.waitSend = 0;
    ChrgM_Output.protocol = UNDEFINE;
#ifdef VF_USE_NX_SECURE
    PnCHlp_Init();
#endif
}
 
template <typename T>
static void getEvStatus(T &status)
{
    if ((ChrgM_Input.stEvccErrLvl > 1) || (ChrgM_Input.bEmgcyShtdn == 1)) {
        status.EVReady = 0;
    } else {
        status.EVReady = 1;
    }
    status.EVErrorCode = static_cast<decltype(status.EVErrorCode)>(ChrgM_Input.stEvErr);
    status.EVRESSSOC = ChrgM_Input.stEvSoc;
}
 
static void handleError(ChrgM_ErrorHandlerType error)
{
    ChrgM_Status.error = error;
    ChrgM_Status.state = ChrgM_Idle;
    SoAd_CloseSoCon(_isTlsConnection() ? SoAdConf_Tls : SoAdConf_Tcp, false);
    if ((V2G_EVCC_MsgTimeout == error) || (V2G_EVCC_CommunicationSetupTimeout == error)) {
        ChrgM_Output.retryTrigger = 1;
    }
}
 
static boolean checkCorrespondState(ChrgM_V2gStateType state)
{
    boolean ret = FALSE;
    if (state != ChrgM_Status.state)
    {
        ret = TRUE;
    }
    return ret;
}
 
static boolean _isAcMode(void)
{
    return ChrgM_Output.stEvseChMode <=
                 iso2_EnergyTransferModeType_AC_three_phase_core;
}
 
boolean ChrgM_Invalid_CPStatus(ChrgM_CpStatus status)
{
    return ((ChrgM_Input.stChPlgCP_2 != status) && (ChrgM_Input.stChPlgCP_2 != (status + 1)));
}
 
/* [V2G2-482] */
#define CHECK_STATE(state) {                                \
    if (checkCorrespondState(state)) {                        \
        handleError(CHRGM_SequenceError);                       \
        return FAILED_SequenceError;                            \
    }                                                         \
}
 
#define RESPONSE_CHECK(resp) {                                                                                      \
    CHECK_STATE(resp);                                                                  \
    ChrgM_Output.stEvseRespCode = doc->V2G_Message.Body.resp.ResponseCode;  \
    if (doc->V2G_Message.Body.resp.ResponseCode                                 \
            >= (uint8_t)iso2_responseCodeType_FAILED) {                         \
        handleError(CHRGM_FAILED);                                              \
        return FAILED;                                                          \
    }                                                                           \
}
 
#define MHU_STOP_CHARGING() {                                                                                                               \
    if((ChrgM_Status.state <= PreChargeRes) && (ChrgM_Status.stChgEndPre == 1)) {       \
        handleError(CHRGM_Error_None);                                                                                                  \
        return Ok;                                                                                                                                          \
    }                                                                                                                                                                   \
}
 
template <typename T>
static void handleDcStatus(const T *status)
{
    if (status->EVSEIsolationStatus_isUsed) {
        ChrgM_Output.stEvseIso = status->EVSEIsolationStatus;
    }
    ChrgM_Output.stEvseNotif = status->EVSENotification;
    ChrgM_Output.stEvse = status->EVSEStatusCode;
    ChrgM_Output.tiEvseNotifMaxDly = status->NotificationMaxDelay;
}
 
template <typename T>
static void handleAcStatus(const T *status)
{
    ChrgM_Output.stEvseNotif = status->EVSENotification;
    ChrgM_Output.tiEvseNotifMaxDly = status->NotificationMaxDelay;
    ChrgM_Output.bEvseRcdErr = status->RCD;
}
 
static void sendSdp(void)
{
    size_t index = V2GTP_HEADER_LENGTH;
    /* [V2G2-128][V2G2-142][V2G2-622][V2G2-623] */
    if (IS_SECURE) {
        ChrgM_Status.buffer[index] = 0x00;
    } else {
        ChrgM_Status.buffer[index] = 0x10;
    }
    index++;
    ChrgM_Status.buffer[index] = 0x00;
    index++;
    /* [V2G2-129][V2G2-141][V2G2-140] */
    V2GTP20_WriteHeader(ChrgM_Status.buffer, 2,
                                            V2GTP20_SDP_REQUEST_PAYLOAD_ID);
    PduInfoType pdu;
    pdu.SduLength = index;
    pdu.SduDataPtr = ChrgM_Status.buffer;
    SoAd_OpenSoCon(SoAdConf_Udp);
    SoAd_IfTransmit(SoAdConf_Udp, &pdu);
}
 
static ChrgM_ResponseCodeType ChrgM_handleSdp(uint8* buffer, uint32_t size)
{
    uint32 payloadLength;
    int ret = V2GTP20_ReadHeader(buffer, &payloadLength,
                                            V2GTP20_SDP_RESPONSE_PAYLOAD_ID);
    /* [V2G2-153][V2G2-152] */
    if ((ret != V2GTP_ERROR__NO_ERROR)||(payloadLength != 20)
            || (size < (payloadLength + V2GTP_HEADER_LENGTH))) {
        return FAILED;
    }
    /* [V2G2-154][V2G2-155][V2G2-156] */
    memset(ChrgM_Status.seccIp, 0, sizeof(ChrgM_Status.seccIp));
    uint8 *data = &buffer[V2GTP_HEADER_LENGTH];
    for (int i = 0; i < 16; i++) {
        ChrgM_Status.seccIp[i/4] <<= 8;
        ChrgM_Status.seccIp[i/4] += data[i];
    }
    ChrgM_Status.seccPort = ((uint16)data[SDP_SECC_PORT_OFFSET] << 8)
        + data[SDP_SECC_PORT_OFFSET + 1];
    ChrgM_Status.seccSecurity = data[SDP_SECC_SECURITY_OFFSET];
 
    if(ChrgM_Status.state == ChrgM_Sdp) {
        /* [V2G2-158] */
        ChrgM_Status.sdpCount = 0;
        ChrgM_Status.state = ChrgM_Connect;
        TcpIp_SockAddrInet6Type addr;
        addr.domain = TCPIP_AF_INET6;
        addr.port = ChrgM_Status.seccPort;
        for (int i = 0; i < 4; i++) {
            addr.addr[i] = ChrgM_Status.seccIp[i];
        }
        SoAd_SetRemoteAddr(_isTlsConnection() ? SoAdConf_Tls : SoAdConf_Tcp, (const TcpIp_SockAddrType *)&addr);
        SoAd_OpenSoCon(_isTlsConnection() ? SoAdConf_Tls : SoAdConf_Tcp);
    }
    return Ok;
}
 
/* ========================================================================= */
template <typename T>
static void addSessionId(T *doc)
{
    /* [V2G2-747] */
    memcpy(doc->V2G_Message.Header.SessionID.bytes, ChrgM_Status.session,
                ChrgM_Status.sessionIDLen);
    doc->V2G_Message.Header.SessionID.bytesLen = ChrgM_Status.sessionIDLen;
}
 
inline void init_exiDocument(struct iso2_exiDocument *doc)
{
    init_iso2_exiDocument(doc);
}
inline void init_exiDocument(struct din_exiDocument *doc)
{
    init_din_exiDocument(doc);
}
 
inline int decode_exiDocument(exi_bitstream_t *stream, iso2_exiDocument *doc)
{
    return decode_iso2_exiDocument(stream, doc);
}
 
inline int decode_exiDocument(exi_bitstream_t *stream, din_exiDocument *doc)
{
    return decode_din_exiDocument(stream, doc);
}
 
template <typename T>
static void prepareExi(T *doc)
{
    init_exiDocument(doc);
    /* [V2G2-752] */
    addSessionId(doc);
}
#ifdef VF_USE_NX_SECURE
#define BCD_TO_DEC(b)   ( ((b) >> 4) * 10 + ((b) & 0x0F) )
#define SECONDS_PER_DAY (86400UL)
/* ========================================================================= */
static ChrgM_ErrorHandlerType handleCheckCertificate(void)
{
    /* X.509 expiration check is mostly ASN.1/time metadata handling.
     * Keep it in software unless the platform exposes a certificate validation service.
     * Hardware crypto is more useful for ECDSA verify/sign, ECDH, SHA-256 and AES below.
     */
    uint8_t date_time[6] = {0};
    UINT status;
    UCHAR asn1_time[14];
    ULONG unix_time = 0;
    ULONG future = 10*SECONDS_PER_DAY; // Expired within 10days 
    //DcmDidMgr_DataServices_Global_Time_ReadData(0, date_time);
    /* Build ASCII UTCTime format "YYMMDDhhmmssZ"*/
    asn1_time[0]  = '0' + (BCD_TO_DEC(date_time[0]) / 10);
    asn1_time[1]  = '0' + (BCD_TO_DEC(date_time[0]) % 10);
    asn1_time[2]  = '0' + (BCD_TO_DEC(date_time[1]) / 10);
    asn1_time[3]  = '0' + (BCD_TO_DEC(date_time[1]) % 10);
    asn1_time[4]  = '0' + (BCD_TO_DEC(date_time[2]) / 10);
    asn1_time[5]  = '0' + (BCD_TO_DEC(date_time[2]) % 10);
    asn1_time[6]  = '0' + (BCD_TO_DEC(date_time[3]) / 10);
    asn1_time[7]  = '0' + (BCD_TO_DEC(date_time[3]) % 10);
    asn1_time[8]  = '0' + (BCD_TO_DEC(date_time[4]) / 10);
    asn1_time[9]  = '0' + (BCD_TO_DEC(date_time[4]) % 10);
    asn1_time[10] = '0' + (BCD_TO_DEC(date_time[5]) / 10);
    asn1_time[11] = '0' + (BCD_TO_DEC(date_time[5]) % 10);
    asn1_time[12] = 'Z';
    status = PnCHlp_Asn1UtcTimeToUnix(asn1_time, sizeof(asn1_time), NX_SECURE_ASN_TAG_UTC_TIME, &unix_time);
    if (status != NX_SECURE_X509_SUCCESS)
    {
        return CHRGM_FAILED;
    }
    if((gPnCHelper.contract[0].contract_cert.cert.nx_secure_x509_certificate_data == NULL) || 
            (gPnCHelper.contract[0].contract_cert.cert.nx_secure_x509_private_key.ec_private_key.nx_secure_ec_private_key == NULL) ||
            (ChrgM_Status.eMAIDLen == 0)) {
        return CHRGM_NoCertificateAvailable;
    }
    if((_nx_secure_x509_expiration_check(&gPnCHelper.contract[0].contract_cert.cert, unix_time) == NX_SECURE_X509_CERTIFICATE_EXPIRED)) {
        return CHRGM_CertificateExpired;
    }
    if((_nx_secure_x509_expiration_check(&gPnCHelper.contract[0].contract_cert.cert, (unix_time + future)) == NX_SECURE_X509_CERTIFICATE_EXPIRED)) {
        return CHRGM_CertificateExpiredSoon;
    }
    
    return CHRGM_Error_None;
}
#endif
/* ========================================================================= */
static void transmitV2gTcp(exi_bitstream_t *stream)
{
    size_t len = 0;
    len = exi_bitstream_get_length(stream);
    PduInfoType pdu = {
        .SduDataPtr = stream->data,
        .SduLength = len + V2GTP_HEADER_LENGTH
    };
    V2GTP_WriteHeader(stream->data, len);
    SoAd_IfTransmit(_isTlsConnection() ? SoAdConf_Tls : SoAdConf_Tcp, &pdu);
}
 
/* ========================================================================= */
inline void encode_Document(exi_bitstream_t *stream, iso2_exiDocument *doc)
{
    encode_iso2_exiDocument(stream, doc);
}
 
inline void encode_Document(exi_bitstream_t *stream, din_exiDocument *doc)
{
    encode_din_exiDocument(stream, doc);
}
template <typename T>
static void transmitExi(T *doc)
{
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, ChrgM_Status.buffer, MAX_MESSAGEBUFFER,
                                            V2GTP_HEADER_LENGTH, NULL);
    encode_Document(&stream, doc);
    transmitV2gTcp(&stream);
}
 
/* ========================================================================= */
static void sendAppHandshake(void)
{
    const char *ns[] = {"urn:din:70121:2012:MsgDef", "urn:iso:15118:2:2013:MsgDef"};
    uint8_t numOfAppProtocol = sizeof(ns) / sizeof(ns[0]);
    struct appHand_exiDocument doc = {0};
    init_appHand_exiDocument(&doc);
    doc.supportedAppProtocolReq_isUsed = 1;
    init_appHand_supportedAppProtocolReq(&doc.supportedAppProtocolReq);
    /* [V2G2-167][V2G2-175] */
    doc.supportedAppProtocolReq.AppProtocol.arrayLen = numOfAppProtocol;
    struct appHand_AppProtocolType *protocol;
 
    for (uint8_t i = 0; i < numOfAppProtocol; i++)
    {
        protocol = &doc.supportedAppProtocolReq.AppProtocol.array[i];
        memset(protocol->ProtocolNamespace.characters, 0,
                        appHand_ProtocolNamespace_CHARACTER_SIZE);
        protocol->ProtocolNamespace.charactersLen = strlen(ns[i]);
        memcpy(protocol->ProtocolNamespace.characters, ns[i], protocol->ProtocolNamespace.charactersLen);
        protocol->SchemaID = 1 - i;
        protocol->Priority = 2 - i;
        protocol->VersionNumberMajor = 2;
        protocol->VersionNumberMinor = 0;
    }
 
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, ChrgM_Status.buffer, MAX_MESSAGEBUFFER,
                                            V2GTP_HEADER_LENGTH, NULL);
    encode_appHand_exiDocument(&stream, &doc);
    /* [V2G2-484] */
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_SupportedAppProtocolReq_Timeout);
    transmitV2gTcp(&stream);
}
 
/* ========================================================================= */
void ChrgM_onConnect(void)
{
    ChrgM_Status.state = ChrgM_supportedAppProtocolRes;
    /* [V2G2-165][V2G2-166][V2G2-483] */
    sendAppHandshake();
}
 
void ChrgM_SoConModeChg(SoAd_SoConIdType SoConId, SoAd_SoConModeType Mode)
{
    if (((SoConId == SoAdConf_Tcp) || (SoConId == SoAdConf_Tls)) && (Mode == SOAD_SOCON_ONLINE)) {
        ChrgM_onConnect();
    }else if(((SoConId == SoAdConf_Tcp) || (SoConId == SoAdConf_Tls)) && (Mode == SOAD_SOCON_OFFLINE)){
        if((ChrgM_Status.state > ChrgM_Connect) && (ChrgM_Status.state != SessionStopRes)){
            handleError(CHRGM_ConnectDropped);
        }else{
            EVCCSlac_Terminate(); /*Terminate to SetKey*/
        }
    }
}
 
/* ========================================================================= */
static void init_MessageHeaderType(struct iso2_MessageHeaderType *header)
{
    init_iso2_MessageHeaderType(header);
}
static void init_MessageHeaderType(struct din_MessageHeaderType *header)
{
    init_din_MessageHeaderType(header);
}
 
DEF_INIT_MSG(SessionSetupReqType)
template <typename T>
static void sendSessionSetupReq(T *doc)
{
    init_exiDocument(doc);
    /* [V2G2-746] */
    init_MessageHeaderType(&doc->V2G_Message.Header);
    memset(doc->V2G_Message.Header.SessionID.bytes, 0,
                    iso2_sessionIDType_BYTES_SIZE);
    doc->V2G_Message.Header.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE;
    doc->V2G_Message.Body.SessionSetupReq_isUsed = 1;
    init_SessionSetupReqType(&doc->V2G_Message.Body.SessionSetupReq);
    /* [V2G2-879][V2G2-188] */
    doc->V2G_Message.Body.SessionSetupReq.EVCCID.bytesLen =
            iso2_evccIDType_BYTES_SIZE;
    EthIf_GetPhysAddr(0, ChrgM_Status.macAddress);
    memcpy(doc->V2G_Message.Body.SessionSetupReq.EVCCID.bytes,
                    ChrgM_Status.macAddress, iso2_evccIDType_BYTES_SIZE);
    /* [V2G2-486] */
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_SessionSetupReq_Timeout);
    transmitExi(doc);
}
#ifdef VF_USE_NX_SECURE
 
/* ========================================================================= */
static boolean copyBoundedBytes(uint8_t *dst, uint16_t dst_size, const uint8_t *src, ULONG src_len)
{
    if ((src == NULL) || (src_len == 0) || (src_len > dst_size)) {
        return FALSE;
    }

    memcpy(dst, src, src_len);
    return TRUE;
}

static boolean copyBoundedString(char *dst, uint16_t dst_size, const char *src, uint16_t src_len)
{
    if ((src == NULL) || (src_len == 0) || (src_len >= dst_size)) {
        return FALSE;
    }

    memcpy(dst, src, src_len);
    return TRUE;
}

static boolean appendDnComponent(char *dst, uint16_t dst_size, uint16_t *offset,
                                const char *prefix, const UCHAR *value, uint16_t value_len)
{
    if ((value == NULL) || (value_len == 0)) {
        return TRUE;
    }

    uint16_t prefix_len = (uint16_t)strlen(prefix);
    uint16_t sep_len = (*offset == 0) ? 0 : 1;
    if ((*offset + sep_len + prefix_len + value_len) >= dst_size) {
        return FALSE;
    }

    if (sep_len != 0) {
        dst[*offset] = ',';
        (*offset)++;
    }
    memcpy(&dst[*offset], prefix, prefix_len);
    *offset += prefix_len;
    memcpy(&dst[*offset], value, value_len);
    *offset += value_len;
    return TRUE;
}

static boolean fillRootCertificateId(struct iso2_X509IssuerSerialType *certId,
                                     const NX_SECURE_X509_CERT *cert)
{
    const UCHAR *serial = cert->nx_secure_x509_issuer.nx_secure_x509_serial_number;
    uint16_t serial_len = cert->nx_secure_x509_issuer.nx_secure_x509_serial_number_length;
    uint16_t issuer_len = 0;

    init_iso2_X509IssuerSerialType(certId);

    if (!appendDnComponent(certId->X509IssuerName.characters, iso2_X509IssuerName_CHARACTER_SIZE,
                           &issuer_len, "C=",
                           cert->nx_secure_x509_issuer.nx_secure_x509_country,
                           cert->nx_secure_x509_issuer.nx_secure_x509_country_length)) {
        return FALSE;
    }
    if (!appendDnComponent(certId->X509IssuerName.characters, iso2_X509IssuerName_CHARACTER_SIZE,
                           &issuer_len, "O=",
                           cert->nx_secure_x509_issuer.nx_secure_x509_organization,
                           cert->nx_secure_x509_issuer.nx_secure_x509_organization_length)) {
        return FALSE;
    }
    if (!appendDnComponent(certId->X509IssuerName.characters, iso2_X509IssuerName_CHARACTER_SIZE,
                           &issuer_len, "CN=",
                           cert->nx_secure_x509_issuer.nx_secure_x509_common_name,
                           cert->nx_secure_x509_issuer.nx_secure_x509_common_name_length)) {
        return FALSE;
    }
    if ((issuer_len == 0) || (serial == NULL) || (serial_len == 0)) {
        return FALSE;
    }

    while ((serial_len > 1) && (*serial == 0x00)) {
        serial++;
        serial_len--;
    }

    certId->X509IssuerName.charactersLen = issuer_len;
    certId->X509SerialNumber.is_negative = 0;
    return (exi_basetypes_convert_bytes_to_unsigned(&certId->X509SerialNumber.data,
                                                    serial, serial_len) == EXI_ERROR__NO_ERROR);
}

static boolean fillListOfRootCertificateIds(struct iso2_ListOfRootCertificateIDsType *list)
{
    uint16_t root_count = gPnCHelper.len_v2g_root;

    init_iso2_ListOfRootCertificateIDsType(list);
    if ((root_count == 0) || (root_count > iso2_X509IssuerSerialType_5_ARRAY_SIZE)) {
        return FALSE;
    }

    list->RootCertificateID.arrayLen = root_count;
    for(uint16_t i = 0; i < root_count; i++)
    {
        if (!fillRootCertificateId(&list->RootCertificateID.array[i],
                                   &gPnCHelper.v2g_root[i].cert)) {
            return FALSE;
        }
    }
    return TRUE;
}

static boolean isValidCertificateChain(const struct iso2_CertificateChainType *chain)
{
    if ((chain->Certificate.bytesLen == 0) ||
            (chain->Certificate.bytesLen > iso2_certificateType_BYTES_SIZE)) {
        return FALSE;
    }
    if (chain->SubCertificates_isUsed &&
            (chain->SubCertificates.Certificate.arrayLen > iso2_certificateType_4_ARRAY_SIZE)) {
        return FALSE;
    }
    if (chain->SubCertificates_isUsed) {
        for(uint16_t i = 0; i < chain->SubCertificates.Certificate.arrayLen; i++) {
            uint16_t cert_len = chain->SubCertificates.Certificate.array[i].bytesLen;
            if ((cert_len == 0) || (cert_len > iso2_certificateType_BYTES_SIZE)) {
                return FALSE;
            }
        }
    }
    return TRUE;
}

/* ========================================================================= */
DEF_INIT_MSG(CertificateInstallationReqType)
template <typename T>
static void sendCertificateInstallationReq(T *doc);
 
template <>
void sendCertificateInstallationReq<iso2_exiDocument>(iso2_exiDocument *doc)
{
    prepareExi(doc);
 
    doc->V2G_Message.Body.CertificateInstallationReq_isUsed = 1u;
    init_iso2_CertificateInstallationReqType(&doc->V2G_Message.Body.CertificateInstallationReq);
    struct iso2_CertificateInstallationReqType *req = &doc->V2G_Message.Body.CertificateInstallationReq;

    uint16_t pcid_len = (uint16_t)strlen((CHAR*)gPnCHelper.pcid);
    ULONG cert_len = gPnCHelper.oem_pvn.cert.nx_secure_x509_certificate_data_length;

    if (!copyBoundedString(req->Id.characters, iso2_Id_CHARACTER_SIZE,
                           (const char*)gPnCHelper.pcid, pcid_len)) {
        handleError(CHRGM_FAILED);
        return;
    }
    req->Id.charactersLen = pcid_len;

    if (!copyBoundedBytes(req->OEMProvisioningCert.bytes, iso2_certificateType_BYTES_SIZE,
                          gPnCHelper.oem_pvn.cert.nx_secure_x509_certificate_data,
                          cert_len)) {
        handleError(CHRGM_FAILED);
        return;
    }
    req->OEMProvisioningCert.bytesLen = (uint16_t)cert_len;

    if (!fillListOfRootCertificateIds(&req->ListOfRootCertificateIDs)) {
        handleError(CHRGM_FAILED);
        return;
    }

    /* Hardware crypto candidate: CertificateInstallationReq XMLDSig/ECDSA signing
     * should be offloaded to HSM/Crypto Driver when available so the OEM provisioning
     * private key never leaves secure hardware.
     */
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_CertificateInstallationReq_Timeout);
    transmitExi(doc);
    return;

#if 0
    /* [V2G2-236] */
    /* ID */
    memcpy(req->Id.characters, gPnCHelper.pcid, strlen((CHAR*)gPnCHelper.pcid));
    req->Id.charactersLen = strlen((CHAR*)gPnCHelper.pcid);
 
    /* [V2G2-893] OEMProvisioningCert */
    memcpy(req->OEMProvisioningCert.bytes,
                 gPnCHelper.oem_pvn.cert.nx_secure_x509_certificate_data,
                 gPnCHelper.oem_pvn.cert.nx_secure_x509_certificate_data_length);
    req->OEMProvisioningCert.bytesLen = (USHORT)gPnCHelper.oem_pvn.cert.nx_secure_x509_certificate_data_length;
 
    /*ListOfRootCertificateIDs*/
    init_iso2_ListOfRootCertificateIDsType(&req->ListOfRootCertificateIDs);
    req->ListOfRootCertificateIDs.RootCertificateID.arrayLen = gPnCHelper.len_v2g_root;
    for(uint8_t i = 0; i < gPnCHelper.len_v2g_root; i++)
    {
        struct iso2_X509IssuerSerialType *certId = 
            &req->ListOfRootCertificateIDs.RootCertificateID.array[i];
        init_iso2_X509IssuerSerialType(certId);
        
        NX_SECURE_X509_CERT *cert = &gPnCHelper.v2g_root[i].cert;
        /* 1. Convert Issuer DN → string */
        uint16_t issuer_data_len = 0;
        memcpy(certId->X509IssuerName.characters, cert->nx_secure_x509_issuer.nx_secure_x509_country, \
                     cert->nx_secure_x509_issuer.nx_secure_x509_country_length);
        issuer_data_len = cert->nx_secure_x509_issuer.nx_secure_x509_country_length;
 
        memcpy(&certId->X509IssuerName.characters[issuer_data_len], cert->nx_secure_x509_issuer.nx_secure_x509_organization, \
                        cert->nx_secure_x509_issuer.nx_secure_x509_organization_length);
        issuer_data_len += cert->nx_secure_x509_issuer.nx_secure_x509_organization_length;
 
        memcpy(&certId->X509IssuerName.characters[issuer_data_len], cert->nx_secure_x509_issuer.nx_secure_x509_common_name, \
                        cert->nx_secure_x509_issuer.nx_secure_x509_common_name_length);
        issuer_data_len += cert->nx_secure_x509_issuer.nx_secure_x509_common_name_length;
 
        certId->X509IssuerName.charactersLen = issuer_data_len;
 
        /* 2. SerialNumber → EXI integer */
        memcpy(certId->X509SerialNumber.data.octets, cert->nx_secure_x509_issuer.nx_secure_x509_serial_number, \
                     cert->nx_secure_x509_issuer.nx_secure_x509_serial_number_length);
        certId->X509SerialNumber.data.octets_count = cert->nx_secure_x509_issuer.nx_secure_x509_serial_number_length;
    }
 
    /* --------------------------------------------------------------------
    * 5. Nếu cần ký XML thì gọi hàm ký riêng (XML Signature)
    * -------------------------------------------------------------------- */
    // PnCHlp_SignatureAdd(&doc->V2G_Message, &gPnCHelper.oem_pvn.Key, &gPnCHelper.oem_pvn.Cert);
    // (phụ thuộc vào stack của bạn — giai đoạn này bắt buộc phải có chữ ký XML)
 
    /* --------------------------------------------------------------------
     * 6. Mã hóa EXI và gửi
     * -------------------------------------------------------------------- */
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_CertificateInstallationReq_Timeout);
    transmitExi(doc);
#endif
}
 
template <>
void sendCertificateInstallationReq<din_exiDocument>(din_exiDocument *doc)
{
 
}
/* ========================================================================= */
DEF_INIT_MSG(CertificateUpdateReqType)
template <typename T>
static void sendCertificateUpdateReq(T *doc);
 
template <>
void sendCertificateUpdateReq<iso2_exiDocument>(iso2_exiDocument *doc)
{
    prepareExi(doc);
 
    doc->V2G_Message.Body.CertificateUpdateReq_isUsed = 1u;
    init_iso2_CertificateUpdateReqType(&doc->V2G_Message.Body.CertificateUpdateReq);
    struct iso2_CertificateUpdateReqType *req = &doc->V2G_Message.Body.CertificateUpdateReq;

    /* Step 1: Id - request identifier used by ISO 15118-2/XMLDSig references. */
    uint16_t pcid_len = (uint16_t)strlen((CHAR*)gPnCHelper.pcid);
    if (!copyBoundedString(req->Id.characters, iso2_Id_CHARACTER_SIZE,
                           (const char*)gPnCHelper.pcid, pcid_len)) {
        handleError(CHRGM_FAILED);
        return;
    }
    req->Id.charactersLen = pcid_len;

    /* Step 2: ContractSignatureCertChain - current contract certificate to be renewed. */
    ULONG contract_cert_len =
        gPnCHelper.contract[0].contract_cert.cert.nx_secure_x509_certificate_data_length;
    req->ContractSignatureCertChain.Id_isUsed = 0u;
    req->ContractSignatureCertChain.SubCertificates_isUsed = 0u;
    if (!copyBoundedBytes(req->ContractSignatureCertChain.Certificate.bytes,
                          iso2_certificateType_BYTES_SIZE,
                          gPnCHelper.contract[0].contract_cert.cert.nx_secure_x509_certificate_data,
                          contract_cert_len)) {
        handleError(CHRGM_FAILED);
        return;
    }
    req->ContractSignatureCertChain.Certificate.bytesLen = (uint16_t)contract_cert_len;

    /* Step 3: eMAID - mandatory account identifier bound to the contract certificate. */
    if (!copyBoundedString(req->eMAID.characters, iso2_eMAID_CHARACTER_SIZE,
                           (const char*)ChrgM_Status.eMAID, ChrgM_Status.eMAIDLen)) {
        handleError(CHRGM_FAILED);
        return;
    }
    req->eMAID.charactersLen = ChrgM_Status.eMAIDLen;

    /* Step 4: ListOfRootCertificateIDs - V2G roots the EV accepts from the SECC. */
    if (!fillListOfRootCertificateIds(&req->ListOfRootCertificateIDs)) {
        handleError(CHRGM_FAILED);
        return;
    }

    /* Step 5: Header.Signature must be added by the XMLDSig helper before EXI encode.
     * Hardware crypto candidate: CertificateUpdateReq XMLDSig/ECDSA signing can be
     * offloaded to HSM/Crypto Driver using the contract private key from secure storage.
     */
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_CertificateUpdateReq_Timeout);
    transmitExi(doc);
    return;

#if 0
    /* [V2G2-228] */
    /* ID */
    memcpy(req->Id.characters, gPnCHelper.pcid, strlen((CHAR*)gPnCHelper.pcid));
    req->Id.charactersLen = strlen((CHAR*)gPnCHelper.pcid);
 
    /* CertificateChain */
    req->ContractSignatureCertChain.Id_isUsed = 1;
    req->ContractSignatureCertChain.SubCertificates_isUsed = 0;
    memcpy(req->ContractSignatureCertChain.Certificate.bytes,
                 gPnCHelper.contract[0].contract_cert.cert.nx_secure_x509_certificate_data,
                 gPnCHelper.contract[0].contract_cert.cert.nx_secure_x509_certificate_data_length);
    req->ContractSignatureCertChain.Certificate.bytesLen = (USHORT)gPnCHelper.contract[0].contract_cert.cert.nx_secure_x509_certificate_data_length;
 
    /* eMAID */
    
    /*ListOfRootCertificateIDs*/
    init_iso2_ListOfRootCertificateIDsType(&req->ListOfRootCertificateIDs);
    req->ListOfRootCertificateIDs.RootCertificateID.arrayLen = gPnCHelper.len_v2g_root;
    for(uint8_t i = 0; i < gPnCHelper.len_v2g_root; i++)
    {
        struct iso2_X509IssuerSerialType *certId = 
            &req->ListOfRootCertificateIDs.RootCertificateID.array[i];
        init_iso2_X509IssuerSerialType(certId);
        
        NX_SECURE_X509_CERT *cert = &gPnCHelper.v2g_root[i].cert;
        /* 1. Convert Issuer DN → string */
        uint16_t issuer_data_len = 0;
        memcpy(certId->X509IssuerName.characters, cert->nx_secure_x509_issuer.nx_secure_x509_country, \
                     cert->nx_secure_x509_issuer.nx_secure_x509_country_length);
        issuer_data_len = cert->nx_secure_x509_issuer.nx_secure_x509_country_length;
 
        memcpy(&certId->X509IssuerName.characters[issuer_data_len], cert->nx_secure_x509_issuer.nx_secure_x509_organization, \
                        cert->nx_secure_x509_issuer.nx_secure_x509_organization_length);
        issuer_data_len += cert->nx_secure_x509_issuer.nx_secure_x509_organization_length;
 
        memcpy(&certId->X509IssuerName.characters[issuer_data_len], cert->nx_secure_x509_issuer.nx_secure_x509_common_name, \
                        cert->nx_secure_x509_issuer.nx_secure_x509_common_name_length);
        issuer_data_len += cert->nx_secure_x509_issuer.nx_secure_x509_common_name_length;
 
        certId->X509IssuerName.charactersLen = issuer_data_len;
 
        /* 2. SerialNumber → EXI integer */
        memcpy(certId->X509SerialNumber.data.octets, cert->nx_secure_x509_issuer.nx_secure_x509_serial_number, \
                     cert->nx_secure_x509_issuer.nx_secure_x509_serial_number_length);
        certId->X509SerialNumber.data.octets_count = cert->nx_secure_x509_issuer.nx_secure_x509_serial_number_length;
    }
 
    /* --------------------------------------------------------------------
    * 5. Nếu cần ký XML thì gọi hàm ký riêng (XML Signature)
    * -------------------------------------------------------------------- */
    // PnCHlp_SignatureAdd(&doc->V2G_Message, &gPnCHelper.oem_pvn.Key, &gPnCHelper.oem_pvn.Cert);
    // (phụ thuộc vào stack của bạn — giai đoạn này bắt buộc phải có chữ ký XML)
 
    /* --------------------------------------------------------------------
     * 6. Mã hóa EXI và gửi
     * -------------------------------------------------------------------- */
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_CertificateUpdateReq_Timeout);
    transmitExi(doc);
#endif
}
 
template <>
void sendCertificateUpdateReq<din_exiDocument>(din_exiDocument *doc)
{
 
}
 
#endif
 
/* ========================================================================= */
DEF_INIT_MSG(ServiceDiscoveryReqType)
template <typename T>
static void sendServiceDiscovery(T *doc)
{
    prepareExi(doc);
    doc->V2G_Message.Body.ServiceDiscoveryReq_isUsed = 1u;
    init_ServiceDiscoveryReqType(&doc->V2G_Message.Body.ServiceDiscoveryReq);
    doc->V2G_Message.Body.ServiceDiscoveryReq.ServiceCategory_isUsed = 1;
    doc->V2G_Message.Body.ServiceDiscoveryReq.ServiceCategory = \
    static_cast<decltype(doc->V2G_Message.Body.ServiceDiscoveryReq.ServiceCategory)>(0);
    transmitExi(doc);
}
 
/* ========================================================================= */
DEF_INIT_MSG(PaymentServiceSelectionReqType)
template <typename T, typename Option>
static void sendPaymentServiceSelection(T *doc, uint16 id, Option paymentOption)
{
    prepareExi(doc);
    doc->V2G_Message.Body.PaymentServiceSelectionReq_isUsed = 1;
    auto *payment = &doc->V2G_Message.Body.PaymentServiceSelectionReq;
    init_PaymentServiceSelectionReqType(payment);
    payment->SelectedPaymentOption = paymentOption;
    payment->SelectedServiceList.SelectedService.arrayLen = 1;
    auto *service = &payment->SelectedServiceList.SelectedService.array[0];
    service->ServiceID = id;
    service->ParameterSetID_isUsed = 0;
    /* [V2G2-492] */
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_PaymentServiceSelectionReq_Timeout);
    transmitExi(doc);
}
 
#ifdef VF_USE_NX_SECURE
/* ========================================================================= */
DEF_INIT_MSG(PaymentDetailsReqType)
template <typename T>
static void sendPaymentDetailsReq(T *doc)
{
    prepareExi(doc);
    doc->V2G_Message.Body.PaymentDetailsReq_isUsed = 1;
    auto *req = &doc->V2G_Message.Body.PaymentDetailsReq;
    init_PaymentDetailsReqType(req);
    if(ChrgM_Status.payContract) {
        /* [V2G2-205] */
        if constexpr (std::is_same<T, iso2_exiDocument>::value)
        {
            memcpy(req->eMAID.characters, ChrgM_Status.eMAID, ChrgM_Status.eMAIDLen);
            req->eMAID.charactersLen = ChrgM_Status.eMAIDLen;
        }
        /*[V2G2-898]*/
        memcpy(req->ContractSignatureCertChain.Certificate.bytes, \
                     gPnCHelper.contract[0].contract_cert.cert.nx_secure_x509_certificate_data, \
                     gPnCHelper.contract[0].contract_cert.cert.nx_secure_x509_certificate_data_length);
        req->ContractSignatureCertChain.Certificate.bytesLen =
                     (USHORT)gPnCHelper.contract[0].contract_cert.cert.nx_secure_x509_certificate_data_length;
    }
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_PaymentDetailsReq_Timeout);
    transmitExi(doc);
}
#endif
 
/* ========================================================================= */
template <typename T>
static void sendAuthorizationReq(T *doc);
 
template <>
void sendAuthorizationReq<iso2_exiDocument>(iso2_exiDocument *doc)
{
    prepareExi(doc);
    doc->V2G_Message.Body.AuthorizationReq_isUsed = 1;
    /* [V2G2-210] */
    auto *req = &doc->V2G_Message.Body.AuthorizationReq;
    init_iso2_AuthorizationReqType(req);
    if(ChrgM_Status.payContract == 1) {
        req->GenChallenge_isUsed = 1;
        memcpy(req->GenChallenge.bytes, ChrgM_Status.genChallenge, iso2_genChallengeType_BYTES_SIZE);
    } else {
        req->GenChallenge_isUsed = 0;
    }
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_AuthorizationReq_Timeout);
    transmitExi(doc);
}
 
template <>
void sendAuthorizationReq<din_exiDocument>(din_exiDocument *doc)
{
    prepareExi(doc);
    doc->V2G_Message.Body.ContractAuthenticationReq_isUsed = 1;
    /* [V2G2-210] */
    auto *req = &doc->V2G_Message.Body.ContractAuthenticationReq;
    init_din_ContractAuthenticationReqType(req);
    req->GenChallenge_isUsed = 0;
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_AuthorizationReq_Timeout);
    transmitExi(doc);
}
 
/* ========================================================================= */
DEF_INIT_MSG(ChargeParameterDiscoveryReqType)
template <typename T>
static void sendChargeParamDiscoveryReq(T *doc);
 
template <>
void sendChargeParamDiscoveryReq<iso2_exiDocument>(iso2_exiDocument *doc)
{
    prepareExi(doc);
    doc->V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed = 1;
    auto *req = &doc->V2G_Message.Body.ChargeParameterDiscoveryReq;
    init_iso2_ChargeParameterDiscoveryReqType(req);
    if (_isAcMode())
    {
        req->RequestedEnergyTransferMode = ((ChrgM_Input.stObcPhase == 1) 
                                      ? iso2_EnergyTransferModeType_AC_single_phase_core 
                                      : (iso2_EnergyTransferModeType)ChrgM_Output.stEvseChMode);
        req->AC_EVChargeParameter_isUsed = 1;
        auto *ac_charge = &req->AC_EVChargeParameter;
        ac_charge->DepartureTime_isUsed = 0;
        ac_charge->EAmount = ChrgMHlp_encodeEnergy<decltype(ac_charge->EAmount)>(0);
        ac_charge->EVMaxCurrent = ChrgMHlp_encodeCurrent<decltype(ac_charge->EVMaxCurrent)>(ChrgM_Input.iEvAcChMaxLim);
        ac_charge->EVMinCurrent = ChrgMHlp_encodeCurrent<decltype(ac_charge->EVMinCurrent)>(ChrgM_Input.iEvAcChMinLim);
        ac_charge->EVMaxVoltage = ChrgMHlp_encodeVoltage<decltype(ac_charge->EVMaxVoltage)>(ChrgM_Input.uEvAcChMaxLim);
    }
    else
    {
        req->RequestedEnergyTransferMode = iso2_EnergyTransferModeType_DC_extended;
        /* [V2G2-784] */
        req->MaxEntriesSAScheduleTuple_isUsed = 1;
        req->MaxEntriesSAScheduleTuple = 12;
        req->EVChargeParameter_isUsed = 0;
        req->DC_EVChargeParameter_isUsed = 1;
        auto *dc_charge = &req->DC_EVChargeParameter;
        getEvStatus(dc_charge->DC_EVStatus);
 
        dc_charge->DepartureTime_isUsed = 0;
        dc_charge->EVEnergyRequest_isUsed = 0;
        dc_charge->EVMaximumCurrentLimit =
                ChrgMHlp_encodeCurrent<decltype(dc_charge->EVMaximumCurrentLimit)>(ChrgM_Input.iEvDcChMaxLim);
        dc_charge->EVMaximumVoltageLimit =
                ChrgMHlp_encodeVoltage<decltype(dc_charge->EVMaximumVoltageLimit)>(ChrgM_Input.uDcChMaxLim);
        dc_charge->EVMaximumPowerLimit_isUsed = 1;
        dc_charge->EVMaximumPowerLimit = 
                ChrgMHlp_encodePower<decltype(dc_charge->EVMaximumPowerLimit)>(ChrgM_Input.iEvDcChMaxLim*ChrgM_Input.uDcChMaxLim);
    }
 
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_ChargeParameterDiscoveryReq_Timeout);
    transmitExi(doc);
}

template <>
void sendChargeParamDiscoveryReq<din_exiDocument>(din_exiDocument *doc)
{
    prepareExi(doc);
    doc->V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed = 1;
    auto *req = &doc->V2G_Message.Body.ChargeParameterDiscoveryReq;
    init_din_ChargeParameterDiscoveryReqType(req);
 
    req->EVRequestedEnergyTransferType = din_EVRequestedEnergyTransferType_DC_extended;
    /* [V2G2-784] */
    req->DC_EVChargeParameter_isUsed = 1;
    req->EVChargeParameter_isUsed = 0;
    auto *dc_charge = &req->DC_EVChargeParameter;
    getEvStatus(dc_charge->DC_EVStatus);
 
    dc_charge->EVMaximumCurrentLimit =
            ChrgMHlp_encodeCurrent<decltype(dc_charge->EVMaximumCurrentLimit)>(ChrgM_Input.iEvDcChMaxLim);
    dc_charge->EVMaximumVoltageLimit =
            ChrgMHlp_encodeVoltage<decltype(dc_charge->EVMaximumVoltageLimit)>(ChrgM_Input.uDcChMaxLim);
    dc_charge->EVMaximumPowerLimit_isUsed = 1;
    dc_charge->EVMaximumPowerLimit = 
            ChrgMHlp_encodePower<decltype(dc_charge->EVMaximumPowerLimit)>(ChrgM_Input.iEvDcChMaxLim*ChrgM_Input.uDcChMaxLim);
 
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_ChargeParameterDiscoveryReq_Timeout);
    transmitExi(doc);
}
 
/* ========================================================================= */
DEF_INIT_MSG(CableCheckReqType)
template <typename T>
static void sendCableCheckReq(T *doc)
{
    prepareExi(doc);
    auto *req = &doc->V2G_Message.Body.CableCheckReq;
    doc->V2G_Message.Body.CableCheckReq_isUsed = 1u;
    init_CableCheckReqType(req);
    getEvStatus(req->DC_EVStatus);
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_CableCheckReq_Timeout);
    transmitExi(doc);
}
 
/* ========================================================================= */
DEF_INIT_MSG(PreChargeReqType)
template <typename T>
static void sendPrechargeReq(T *doc)
{
    prepareExi(doc);
    auto *req = &doc->V2G_Message.Body.PreChargeReq;
    doc->V2G_Message.Body.PreChargeReq_isUsed = 1u;
    init_PreChargeReqType(req);
    req->EVTargetCurrent = 
            ChrgMHlp_encodeCurrent<decltype(req->EVTargetCurrent)>(2.0);
    req->EVTargetVoltage = 
            ChrgMHlp_encodeVoltage<decltype(req->EVTargetVoltage)>(ChrgM_Input.uDcEvChReq);
    getEvStatus(req->DC_EVStatus);
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_PreChargeReq_Timeout);
    transmitExi(doc);
}
 
/* ========================================================================= */
static void setChargeProgress(iso2_PowerDeliveryReqType *req, uint8_t progress)
{
    req->ChargeProgress = static_cast<iso2_chargeProgressType>(progress);
    /*[V2G2-479]*/
    if(ChrgM_Status.SAScheduleID != 0) {
        req->SAScheduleTupleID = ChrgM_Status.SAScheduleID;
    } else {
        req->SAScheduleTupleID = 1;
    }
    req->ChargingProfile_isUsed = 0;
}
 
static void setChargeProgress(din_PowerDeliveryReqType *req, uint8_t progress)
{
    req->ReadyToChargeState = progress;
}
 
DEF_INIT_MSG(PowerDeliveryReqType)
template <typename T>
static void sendPowerDeliveryReq(T *doc, uint8_t progress)
{
    prepareExi(doc);
    auto *req = &doc->V2G_Message.Body.PowerDeliveryReq;
    doc->V2G_Message.Body.PowerDeliveryReq_isUsed = 1;
    init_PowerDeliveryReqType(req);
 
    setChargeProgress(req, progress);
 
    if (!_isAcMode())
    {
        req->DC_EVPowerDeliveryParameter_isUsed = 1;
        getEvStatus(req->DC_EVPowerDeliveryParameter.DC_EVStatus);
        req->DC_EVPowerDeliveryParameter.BulkChargingComplete_isUsed = 0;
        if constexpr (std::is_same<T, iso2_exiDocument>::value)
        {
            req->DC_EVPowerDeliveryParameter.ChargingComplete = progress;
        }
        else if constexpr (std::is_same<T, din_exiDocument>::value)
        {
            req->DC_EVPowerDeliveryParameter.ChargingComplete = !progress;
        }
    }
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_PowerDeliveryReq_Timeout);
    transmitExi(doc);
}
 
template <typename T>
static void sendPowerDeliveryReqStart(T *doc)
{
    ChrgM_Status.chargeProgress = 1;
    /* [V2G2-836] */
    if constexpr (std::is_same<T, iso2_exiDocument>::value)
    {
        sendPowerDeliveryReq(doc, (uint8_t)iso2_chargeProgressType_Start);
    }
    else if constexpr (std::is_same<T, din_exiDocument>::value)
    {
        sendPowerDeliveryReq(doc, (uint8_t)(1));
    }
}
 
template <typename T>
static void sendPowerDeliveryReqStop(T *doc)
{
    ChrgM_Status.chargeProgress = 0;
    /* [V2G-838] */
    if constexpr (std::is_same<T, iso2_exiDocument>::value)
    {
        sendPowerDeliveryReq(doc, (uint8_t)iso2_chargeProgressType_Stop);
    }
    else if constexpr (std::is_same<T, din_exiDocument>::value)
    {
        sendPowerDeliveryReq(doc, (uint8_t)(0));
    }
}
 
/* ========================================================================= */
DEF_INIT_MSG(CurrentDemandReqType)
template <typename T>
static void sendCurrentDemandReq(T *doc)
{
    prepareExi(doc);
    auto *req = &doc->V2G_Message.Body.CurrentDemandReq;
    doc->V2G_Message.Body.CurrentDemandReq_isUsed = 1u;
    init_CurrentDemandReqType(req);
    getEvStatus(req->DC_EVStatus);
    req->EVMaximumVoltageLimit_isUsed = 1;
    req->EVMaximumVoltageLimit = ChrgMHlp_encodeVoltage<decltype(req->EVMaximumVoltageLimit)>(ChrgM_Input.uDcChMaxLim);
    if((ChrgM_Status.stChgEndPre == 1) || (ChrgM_Input.stEvccErrLvl > 1))
    {
        /* 61851-23 Figure CC.6: Request 0A when error or stop charging*/
        req->EVTargetCurrent = ChrgMHlp_encodeCurrent<decltype(req->EVTargetCurrent)>(0);
        if(ChrgM_Status.triggerStop) {
            ChrgM_Status.shutdownTimer = _setTimer((ChrgM_Output.iEvseDcAct/200.0f)*1000);
            ChrgM_Status.triggerStop = false;
        }
    }
    else
    {
        req->EVTargetCurrent = ChrgMHlp_encodeCurrent<decltype(req->EVTargetCurrent)>(ChrgM_Input.iDcEvChReq);
    }
    req->EVTargetVoltage = ChrgMHlp_encodeVoltage<decltype(req->EVTargetVoltage)>(ChrgM_Input.uDcEvChReq);
    req->ChargingComplete = FALSE;
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_CurrentDemandReq_Timeout);
    transmitExi(doc);
}
 
/* ========================================================================= */
DEF_INIT_MSG(ChargingStatusReqType)
template <typename T>
static void sendChargingStatusReq(T *doc)
{
    prepareExi(doc);
    auto *req = &doc->V2G_Message.Body.ChargingStatusReq;
    doc->V2G_Message.Body.ChargingStatusReq_isUsed = 1U;
    init_ChargingStatusReqType(req);
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_ChargingStatusReq_Timeout);
    transmitExi(doc);
}
 
/* ========================================================================= */
DEF_INIT_MSG(WeldingDetectionReqType)
template <typename T>
static void sendWeldingDetectionReq(T *doc)
{
    prepareExi(doc);
    auto *req = &doc->V2G_Message.Body.WeldingDetectionReq;
    doc->V2G_Message.Body.WeldingDetectionReq_isUsed = 1u;
    init_WeldingDetectionReqType(req);
    getEvStatus(req->DC_EVStatus);
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_WeldingDetectionReq_Timeout);
    transmitExi(doc);
}
 
/* ========================================================================= */
DEF_INIT_MSG(SessionStopReqType)
template <typename T>
static void sendSessionStopReq(T *doc)
{
    prepareExi(doc);
    doc->V2G_Message.Body.SessionStopReq_isUsed = 1;
    init_SessionStopReqType(&doc->V2G_Message.Body.SessionStopReq);
    if constexpr (std::is_same<T, iso2_exiDocument>::value)
    {
        doc->V2G_Message.Body.SessionStopReq.ChargingSession = 
            iso2_chargingSessionType_Terminate;
    }
    ChrgM_Status.MsgTimer = _setTimer(V2G_EVCC_SessionStopReq_Timeout);
    transmitExi(doc);
}
 
/* ========================================================================= */
static void handleAppHandshake(exi_bitstream_t *stream)
{
    struct appHand_exiDocument doc = {0};
    decode_appHand_exiDocument(stream, &doc);
    if (doc.supportedAppProtocolRes_isUsed)
    {
        ChrgM_Output.stEvseRespCode = doc.supportedAppProtocolRes.ResponseCode;
        if (doc.supportedAppProtocolRes.ResponseCode 
                >= appHand_responseCodeType_Failed_NoNegotiation) {
            /* [V2G2-173] */
            handleError(CHRGM_AppHandShakeFail);
        } else {
            if (doc.supportedAppProtocolRes.SchemaID_isUsed) {
                ChrgM_Output.protocol = 
                    (ChargeProtocolType)doc.supportedAppProtocolRes.SchemaID;
            }
            if(ChrgM_Output.protocol >= UNDEFINE) {
                handleError(CHRGM_ProtocolNotSupport);
            } else {
                ChrgM_Status.state = SessionSetupRes;
                SEND_REQ_MSG(SessionSetupReq);
            }
        }
    }
}
 
/* ========================================================================= */
template <typename T>
static ChrgM_ResponseCodeType handleSessionSetupRes(T *doc)
{
    /* [V2G2-190] */
    RESPONSE_CHECK(SessionSetupRes);
    MHU_STOP_CHARGING();
 
    if (doc->V2G_Message.Header.SessionID.bytesLen > iso2_sessionIDType_BYTES_SIZE) {
        handleError(CHRGM_SessionIDLenGreater);
        return FAILED;
    }
    ChrgM_Status.sessionIDLen = doc->V2G_Message.Header.SessionID.bytesLen;
    memcpy(ChrgM_Status.session, doc->V2G_Message.Header.SessionID.bytes,
                    ChrgM_Status.sessionIDLen);
    /* [V2G2-487] */
    ChrgM_Status.state = ServiceDiscoveryRes;
    sendServiceDiscovery(doc);
    return Ok;
}
 
/* ========================================================================= */
#define SUPPORTED_TRANSFER_MODES (3)
#define SUPPORTED_DC_MODES       (0x3CU)  /* 0011 1100 */
template <typename T>
static ChrgM_ResponseCodeType handleServiceDiscoveryRes(T *doc);
 
template <>
ChrgM_ResponseCodeType handleServiceDiscoveryRes<iso2_exiDocument>(struct iso2_exiDocument *doc)
{
    /* [V2G2-492] */
    RESPONSE_CHECK(ServiceDiscoveryRes);
    MHU_STOP_CHARGING();
    auto *res = &doc->V2G_Message.Body.ServiceDiscoveryRes;
    auto *transfer = &res->ChargeService.SupportedEnergyTransferMode;
    iso2_EnergyTransferModeType selectedMode;
    uint8_t transferModeIdx, transferModeMask = 0;
    for(transferModeIdx = 0; transferModeIdx < transfer->EnergyTransferMode.arrayLen; transferModeIdx++)
    {
        transferModeMask |= (1 << transfer->EnergyTransferMode.array[transferModeIdx]);
    }
 
    if(transferModeMask & SUPPORTED_DC_MODES) {
        selectedMode = iso2_EnergyTransferModeType_DC_extended;
    } else {
        selectedMode = (transferModeMask & (1 << iso2_EnergyTransferModeType_AC_three_phase_core))  \
                                        ? iso2_EnergyTransferModeType_AC_three_phase_core                                                   \
                                        : iso2_EnergyTransferModeType_AC_single_phase_core;
    }
    ChrgM_Output.stEvseChMode = selectedMode;
    iso2_paymentOptionType paymentOption = iso2_paymentOptionType_ExternalPayment;
    boolean paymentOptionFound = FALSE;
#ifdef VF_USE_NX_SECURE
    if (_isTlsConnection()) {
        for(uint8_t i = 0; i < res->PaymentOptionList.PaymentOption.arrayLen; i++) {
            if(res->PaymentOptionList.PaymentOption.array[i] == iso2_paymentOptionType_Contract) {
                paymentOption = res->PaymentOptionList.PaymentOption.array[i];
                paymentOptionFound = TRUE;
                break;
            }
        }
    }
#endif
    if (paymentOptionFound == FALSE) {
        for(uint8_t i = 0; i < res->PaymentOptionList.PaymentOption.arrayLen; i++) {
            if(res->PaymentOptionList.PaymentOption.array[i] == iso2_paymentOptionType_ExternalPayment) {
                paymentOption = res->PaymentOptionList.PaymentOption.array[i];
                paymentOptionFound = TRUE;
                break;
            }
        }
    }
    if (paymentOptionFound == FALSE) {
        handleError(CHRGM_FAILED);
        return FAILED;
    }
    /* [V2G2-490] */
    ChrgM_Status.state = PaymentServiceSelectionRes;
    ChrgM_Status.payContract = (paymentOption == iso2_paymentOptionType_Contract ? 1 : 0);
    sendPaymentServiceSelection(&ChrgM_Status.exiDoc.iso2, res->ChargeService.ServiceID, paymentOption);
 
    return Ok;
}
 
template <>
ChrgM_ResponseCodeType handleServiceDiscoveryRes<din_exiDocument>(struct din_exiDocument *doc)
{
    /* [V2G2-492] */
    RESPONSE_CHECK(ServiceDiscoveryRes);
    MHU_STOP_CHARGING();
    auto *res = &doc->V2G_Message.Body.ServiceDiscoveryRes;
    din_EVSESupportedEnergyTransferType selectedMode = res->ChargeService.EnergyTransferType;
    ChrgM_Output.stEvseChMode = selectedMode;
    din_paymentOptionType paymentOption = din_paymentOptionType_ExternalPayment;
    boolean paymentOptionFound = FALSE;
    for(uint8_t i = 0; i < res->PaymentOptions.PaymentOption.arrayLen; i++) {
        if(res->PaymentOptions.PaymentOption.array[i] == din_paymentOptionType_ExternalPayment) {
            paymentOption = res->PaymentOptions.PaymentOption.array[i];
            paymentOptionFound = TRUE;
            break;
        }
    }
    if (paymentOptionFound == FALSE) {
        handleError(CHRGM_FAILED);
        return FAILED;
    }
    /* [V2G2-490] */
    ChrgM_Status.state = PaymentServiceSelectionRes;
    ChrgM_Status.payContract = (paymentOption == din_paymentOptionType_Contract ? 1 : 0);
    sendPaymentServiceSelection(&ChrgM_Status.exiDoc.din, res->ChargeService.ServiceTag.ServiceID, paymentOption);
 
    return Ok;
}
 
#ifdef VF_USE_NX_SECURE
#include "nx_crypto.h"
/* ========================================================================= */
template <typename T>
static ChrgM_ResponseCodeType handleCertificateInstallationRes(T *doc);
 
template <>
ChrgM_ResponseCodeType handleCertificateInstallationRes<iso2_exiDocument>(iso2_exiDocument *doc)
{
    /* [V2G2-492] */
    RESPONSE_CHECK(CertificateInstallationRes);
    MHU_STOP_CHARGING();
    auto *res = &doc->V2G_Message.Body.CertificateInstallationRes;

    /* Step 1: Validate mandatory response payloads from ISO 15118-2 CertificateInstallationRes. */
    if (!isValidCertificateChain(&res->SAProvisioningCertificateChain) ||
            !isValidCertificateChain(&res->ContractSignatureCertChain) ||
            (res->DHpublickey.CONTENT.bytesLen == 0) ||
            (res->ContractSignatureEncryptedPrivateKey.CONTENT.bytesLen <= 16) ||
            (((res->ContractSignatureEncryptedPrivateKey.CONTENT.bytesLen - 16) % 16) != 0) ||
            (res->eMAID.CONTENT.charactersLen == 0) ||
            (res->eMAID.CONTENT.charactersLen >= sizeof(ChrgM_Status.eMAID))) {
        handleError(CHRGM_FAILED);
        return FAILED;
    }

    /* Step 2: Split ContractSignatureEncryptedPrivateKey into AES-CBC IV and ciphertext. */
    uint8_t *iv = &res->ContractSignatureEncryptedPrivateKey.CONTENT.bytes[0];
    uint8_t *cipher = &res->ContractSignatureEncryptedPrivateKey.CONTENT.bytes[16];
    uint16_t cipher_len = res->ContractSignatureEncryptedPrivateKey.CONTENT.bytesLen - 16;

    /* Step 3: ECDH with EVCC private key and SECC DHpublickey to get shared secret Z.
     * Hardware crypto candidate: replace PnCHlp_Shared_Secret_Compute()/crypto_method_ecdh
     * with HSM/Crypto Driver ECDH so the EVCC private key stays inside secure hardware.
     */
    uint8_t shared_secret[32] = {0};
    UINT shared_secret_actual_len = 0;
    PnCHlp_Shared_Secret_Compute(&crypto_method_ecdh, res->DHpublickey.CONTENT.bytes,
                                 res->DHpublickey.CONTENT.bytesLen, shared_secret,
                                 sizeof(shared_secret), &shared_secret_actual_len);
    if (shared_secret_actual_len != sizeof(shared_secret)) {
        handleError(CHRGM_FAILED);
        return FAILED;
    }

    /* Step 4: ISO 15118-2 KDF: SHA256(0x00000001 || Z || 0x01 || 0x55 || 0x56).
     * Hardware crypto candidate: replace PnCHlp_SHA256() with hardware SHA-256
     * when the crypto accelerator supports streaming/hash jobs.
     */
    uint8_t counter[4] = {0x00, 0x00, 0x00, 0x01};
    uint8_t other_info[3] = {0x01, 0x55, 0x56};
    uint8_t kdf_input[4 + sizeof(shared_secret) + 3] = {0};
    uint8_t hash[32] = {0};
    uint8_t aes_key[16] = {0};

    memcpy(kdf_input, counter, sizeof(counter));
    memcpy(kdf_input + sizeof(counter), shared_secret, sizeof(shared_secret));
    memcpy(kdf_input + sizeof(counter) + sizeof(shared_secret), other_info, sizeof(other_info));
    PnCHlp_SHA256(kdf_input, sizeof(kdf_input), hash);
    memcpy(aes_key, hash, sizeof(aes_key));

    /* Step 5: Decrypt contract private key with AES-128-CBC using the derived key.
     * Hardware crypto candidate: replace PnCHlp_DeCryt_ContractPrivateKey()/AES-CBC
     * with HSM/Crypto Driver AES-CBC decrypt and import the key directly to secure storage.
     */
    uint8_t plain_privateKey[128] = {0};
    uint16_t plain_privateKeyLen = 0;
    PnCHlp_DeCryt_ContractPrivateKey(&crypto_method_aes_cbc_128, aes_key, iv, cipher,
                                     cipher_len, plain_privateKey, &plain_privateKeyLen);
    if ((plain_privateKeyLen == 0) || (plain_privateKeyLen > sizeof(plain_privateKey))) {
        handleError(CHRGM_FAILED);
        return FAILED;
    }

    /* Step 6: Store contract certificate/private key and optional sub-CA certificates.
     * Hardware security candidate: private-key persistence should use HSM-backed key
     * import/secure NVM instead of writing plaintext key bytes to software-managed flash.
     */
    struct iso2_CertificateChainType *contract_chain = &res->ContractSignatureCertChain;
    PnCHlp_Contract_Add(contract_chain->Certificate.bytes, contract_chain->Certificate.bytesLen,
                        plain_privateKey, plain_privateKeyLen);
    if(contract_chain->SubCertificates_isUsed) {
        for(uint8_t i = 0; i < contract_chain->SubCertificates.Certificate.arrayLen; i++) {
            PnCHlp_SubContractCA_Add(contract_chain->SubCertificates.Certificate.array[i].bytes,
                                     contract_chain->SubCertificates.Certificate.array[i].bytesLen, i);
        }
    }

    /* Step 7: Store SA provisioning chain for future update requests when storage API is available. */
    /* TODO - Add PnCHlp_SAProvisioning_Add() or equivalent flash persistence. */

    /* Step 8: Cache eMAID for PaymentDetailsReq and later CertificateUpdateReq. */
    memcpy(ChrgM_Status.eMAID, res->eMAID.CONTENT.characters, res->eMAID.CONTENT.charactersLen);
    ChrgM_Status.eMAIDLen = res->eMAID.CONTENT.charactersLen;

    /* Step 9: Continue ISO 15118-2 PnC flow with PaymentDetailsReq. */
    ChrgM_Status.state = PaymentDetailsRes;
    sendPaymentDetailsReq(doc);
    return Ok;

#if 0
 
    /* ContractSignatureEncryptedPrivateKey */
    /*[V2G2-817]*/
    if (res->ContractSignatureEncryptedPrivateKey.CONTENT.bytesLen <= 16) {
        handleError(CHRGM_FAILED);
        return FAILED;
    }
    uint8_t *iv = &res->ContractSignatureEncryptedPrivateKey.CONTENT.bytes[0];
    uint8_t *cipher = &res->ContractSignatureEncryptedPrivateKey.CONTENT.bytes[16];
 
    uint16_t cipher_len = res->ContractSignatureEncryptedPrivateKey.CONTENT.bytesLen - 16;
    /* [V2G2-815]       shared_secret (Z) = ECDH(EVCC_private_key, DHpublickey)
                                    session_key = KDF_SHA256(shared_secret, params) → 128-bit
 
        Hash256(Counter (4 bytes) || Z || OtherInfo) = Hash256(0x00000001 (Big-endian) || Z || 0x01 || 0x55 || 0x56)
    */
    uint8_t shared_secret[32] = {0};
    uint16_t shared_secret_actual_len;
    PnCHlp_Shared_Secret_Compute(&crypto_method_ecdh, res->DHpublickey.CONTENT.bytes, \
                                                                res->DHpublickey.CONTENT.bytesLen, shared_secret, \
                                                                sizeof(shared_secret), (UINT *)&shared_secret_actual_len);
    uint8_t counter[4] = {0x00, 0x00, 0x00, 0x01};
    uint8_t other_info[3] = {0x01, 0x55, 0x56};
 
    uint8_t kdf_input[4 + 32 + 3];
    uint8_t hash[32];
    uint8_t aes_key[16];
 
    memcpy(kdf_input, counter, 4);
    memcpy(kdf_input + 4, shared_secret, 32);
    memcpy(kdf_input + 36, other_info, 3);
 
    PnCHlp_SHA256(kdf_input, sizeof(kdf_input), hash);
    memcpy(aes_key, hash, 16); /* AES-128 key = first 16 bytes of SHA-256( 0x00000001 || Z || 0x01 || 0x55 || 0x56 ) */
    
    uint8_t plain_privateKey[128];
    uint16_t plain_privateKeyLen;
    PnCHlp_DeCryt_ContractPrivateKey(&crypto_method_aes_cbc_128, aes_key, iv, cipher, cipher_len, plain_privateKey, &plain_privateKeyLen);
    /* TODO - Write ContractPrivateKey to Flash */
    
    /* ContractSignatureCertChain */
    struct iso2_CertificateChainType CertChain = res->ContractSignatureCertChain;
    PnCHlp_Contract_Add(CertChain.Certificate.bytes, CertChain.Certificate.bytesLen, plain_privateKey, plain_privateKeyLen);
    if(CertChain.SubCertificates_isUsed) {
        for(uint8_t i = 0; i < CertChain.SubCertificates.Certificate.arrayLen; i++) {
            PnCHlp_SubContractCA_Add(CertChain.SubCertificates.Certificate.array[i].bytes, \
                                                            CertChain.SubCertificates.Certificate.array[i].bytesLen, i);
        }
    }
    /* TODO - Write ContractCertificate to Flash */
 
    /* eMAID */
    memcpy(ChrgM_Status.eMAID, res->eMAID.CONTENT.characters, res->eMAID.CONTENT.charactersLen);
    ChrgM_Status.eMAIDLen = res->eMAID.CONTENT.charactersLen;
    /* TODO - Write eMAID to Flash */
 
    ChrgM_Status.state = PaymentDetailsRes;
    sendPaymentDetailsReq(doc);
 
    return Ok;
#endif
}
 
template <>
ChrgM_ResponseCodeType handleCertificateInstallationRes<din_exiDocument>(din_exiDocument *doc)
{
    return Ok;
}
 
template <typename T>
static ChrgM_ResponseCodeType handleCertificateUpdateRes(T *doc);
 
template <>
ChrgM_ResponseCodeType handleCertificateUpdateRes<iso2_exiDocument>(iso2_exiDocument *doc)
{
    /* [V2G2-492] */
    RESPONSE_CHECK(CertificateUpdateRes);
    MHU_STOP_CHARGING();
 
    auto *res = &doc->V2G_Message.Body.CertificateUpdateRes;

    /* Step 1: Validate mandatory response payloads from ISO 15118-2 CertificateUpdateRes. */
    if (!isValidCertificateChain(&res->ContractSignatureCertChain) ||
            (res->DHpublickey.CONTENT.bytesLen == 0) ||
            (res->ContractSignatureEncryptedPrivateKey.CONTENT.bytesLen <= 16) ||
            (((res->ContractSignatureEncryptedPrivateKey.CONTENT.bytesLen - 16) % 16) != 0) ||
            (res->eMAID.CONTENT.charactersLen == 0) ||
            (res->eMAID.CONTENT.charactersLen >= sizeof(ChrgM_Status.eMAID))) {
        handleError(CHRGM_FAILED);
        return FAILED;
    }

    /* Step 2: Split ContractSignatureEncryptedPrivateKey into AES-CBC IV and ciphertext. */
    uint8_t *iv = &res->ContractSignatureEncryptedPrivateKey.CONTENT.bytes[0];
    uint8_t *cipher = &res->ContractSignatureEncryptedPrivateKey.CONTENT.bytes[16];
    uint16_t cipher_len = res->ContractSignatureEncryptedPrivateKey.CONTENT.bytesLen - 16;

    /* Step 3: ECDH with EVCC private key and SECC DHpublickey to get shared secret Z.
     * Hardware crypto candidate: replace PnCHlp_Shared_Secret_Compute()/crypto_method_ecdh
     * with HSM/Crypto Driver ECDH so the EVCC private key stays inside secure hardware.
     */
    uint8_t shared_secret[32] = {0};
    UINT shared_secret_actual_len = 0;
    PnCHlp_Shared_Secret_Compute(&crypto_method_ecdh, res->DHpublickey.CONTENT.bytes,
                                 res->DHpublickey.CONTENT.bytesLen, shared_secret,
                                 sizeof(shared_secret), &shared_secret_actual_len);
    if (shared_secret_actual_len != sizeof(shared_secret)) {
        handleError(CHRGM_FAILED);
        return FAILED;
    }

    /* Step 4: ISO 15118-2 KDF: SHA256(0x00000001 || Z || 0x01 || 0x55 || 0x56).
     * Hardware crypto candidate: replace PnCHlp_SHA256() with hardware SHA-256
     * when the crypto accelerator supports streaming/hash jobs.
     */
    uint8_t counter[4] = {0x00, 0x00, 0x00, 0x01};
    uint8_t other_info[3] = {0x01, 0x55, 0x56};
    uint8_t kdf_input[4 + sizeof(shared_secret) + 3] = {0};
    uint8_t hash[32] = {0};
    uint8_t aes_key[16] = {0};

    memcpy(kdf_input, counter, sizeof(counter));
    memcpy(kdf_input + sizeof(counter), shared_secret, sizeof(shared_secret));
    memcpy(kdf_input + sizeof(counter) + sizeof(shared_secret), other_info, sizeof(other_info));
    PnCHlp_SHA256(kdf_input, sizeof(kdf_input), hash);
    memcpy(aes_key, hash, sizeof(aes_key));

    /* Step 5: Decrypt updated contract private key with AES-128-CBC using the derived key.
     * Hardware crypto candidate: replace PnCHlp_DeCryt_ContractPrivateKey()/AES-CBC
     * with HSM/Crypto Driver AES-CBC decrypt and import the key directly to secure storage.
     */
    uint8_t plain_privateKey[128] = {0};
    uint16_t plain_privateKeyLen = 0;
    PnCHlp_DeCryt_ContractPrivateKey(&crypto_method_aes_cbc_128, aes_key, iv, cipher,
                                     cipher_len, plain_privateKey, &plain_privateKeyLen);
    if ((plain_privateKeyLen == 0) || (plain_privateKeyLen > sizeof(plain_privateKey))) {
        handleError(CHRGM_FAILED);
        return FAILED;
    }

    /* Step 6: Replace stored contract certificate/private key and optional sub-CA certificates.
     * Hardware security candidate: private-key persistence should use HSM-backed key
     * import/secure NVM instead of writing plaintext key bytes to software-managed flash.
     */
    struct iso2_CertificateChainType *contract_chain = &res->ContractSignatureCertChain;
    PnCHlp_Contract_Add(contract_chain->Certificate.bytes, contract_chain->Certificate.bytesLen,
                        plain_privateKey, plain_privateKeyLen);
    if(contract_chain->SubCertificates_isUsed) {
        for(uint8_t i = 0; i < contract_chain->SubCertificates.Certificate.arrayLen; i++) {
            PnCHlp_SubContractCA_Add(contract_chain->SubCertificates.Certificate.array[i].bytes,
                                     contract_chain->SubCertificates.Certificate.array[i].bytesLen, i);
        }
    }

    /* Step 7: Cache updated eMAID for PaymentDetailsReq and later update checks. */
    memcpy(ChrgM_Status.eMAID, res->eMAID.CONTENT.characters, res->eMAID.CONTENT.charactersLen);
    ChrgM_Status.eMAIDLen = res->eMAID.CONTENT.charactersLen;

    /* Step 8: Continue ISO 15118-2 PnC flow with PaymentDetailsReq. */
    ChrgM_Status.state = PaymentDetailsRes;
    sendPaymentDetailsReq(doc);
    return Ok;

#if 0
    /* ContractSignatureEncryptedPrivateKey */
    /*[V2G2-817]*/
    if (res->ContractSignatureEncryptedPrivateKey.CONTENT.bytesLen <= 16) {
        handleError(CHRGM_FAILED);
        return FAILED;
    }
    uint8_t *iv = &res->ContractSignatureEncryptedPrivateKey.CONTENT.bytes[0];
    uint8_t *cipher = &res->ContractSignatureEncryptedPrivateKey.CONTENT.bytes[16];
 
    uint16_t cipher_len = res->ContractSignatureEncryptedPrivateKey.CONTENT.bytesLen - 16;
    /* [V2G2-815]       shared_secret (Z) = ECDH(EVCC_private_key, DHpublickey)
                                    session_key = KDF_SHA256(shared_secret, params) → 128-bit
 
        Hash256(Counter (4 bytes) || Z || OtherInfo) = Hash256(0x00000001 (Big-endian) || Z || 0x01 || 0x55 || 0x56)
    */
    uint8_t shared_secret[32] = {0};
    uint16_t shared_secret_actual_len;
    PnCHlp_Shared_Secret_Compute(&crypto_method_ecdh, res->DHpublickey.CONTENT.bytes, \
                                                                res->DHpublickey.CONTENT.bytesLen, shared_secret, \
                                                                sizeof(shared_secret), (UINT *)&shared_secret_actual_len);
 
    uint8_t counter[4] = {0x00, 0x00, 0x00, 0x01};
    uint8_t other_info[3] = {0x01, 0x55, 0x56};
 
    uint8_t kdf_input[4 + 32 + 3];
    uint8_t hash[32];
    uint8_t aes_key[16];
 
    memcpy(kdf_input, counter, 4);
    memcpy(kdf_input + 4, shared_secret, 32);
    memcpy(kdf_input + 36, other_info, 3);
 
    PnCHlp_SHA256(kdf_input, sizeof(kdf_input), hash);
    memcpy(aes_key, hash, 16); /* AES-128 key = first 16 bytes of SHA-256( 0x00000001 || Z || 0x01 || 0x55 || 0x56 ) */
    
    uint8_t plain_privateKey[128];
    uint16_t plain_privateKeyLen;
    PnCHlp_DeCryt_ContractPrivateKey(&crypto_method_aes_cbc_128, aes_key, iv, cipher, cipher_len, plain_privateKey, &plain_privateKeyLen);
    /* TODO - Write ContractPrivateKey to Flash */
    
    /* ContractSignatureCertChain */
    struct iso2_CertificateChainType CertChain = res->ContractSignatureCertChain;
    PnCHlp_Contract_Add(CertChain.Certificate.bytes, CertChain.Certificate.bytesLen, plain_privateKey, plain_privateKeyLen);
    if(CertChain.SubCertificates_isUsed) {
        for(uint8_t i = 0; i < CertChain.SubCertificates.Certificate.arrayLen; i++) {
            PnCHlp_SubContractCA_Add(CertChain.SubCertificates.Certificate.array[i].bytes, \
                                                            CertChain.SubCertificates.Certificate.array[i].bytesLen, i);
        }
    }
    /* TODO - Write ContractCertificate to Flash */
 
    /* eMAID */
    memcpy(ChrgM_Status.eMAID, res->eMAID.CONTENT.characters, res->eMAID.CONTENT.charactersLen);
    ChrgM_Status.eMAIDLen = res->eMAID.CONTENT.charactersLen;
    /* TODO - Write eMAID to Flash */
 
    ChrgM_Status.state = PaymentDetailsRes;
    sendPaymentDetailsReq(doc);
 
    return Ok;
#endif
}
 
template <>
ChrgM_ResponseCodeType handleCertificateUpdateRes<din_exiDocument>(din_exiDocument *doc)
{
    return Ok;
}
#endif
/* ========================================================================= */
#ifdef VF_USE_NX_SECURE
template <typename T>
static ChrgM_ResponseCodeType sendNextContractCertificateMessage(T *doc,
                                                                 ChrgM_ErrorHandlerType cert_status)
{
    switch (cert_status)
    {
    case CHRGM_NoCertificateAvailable:
        /* No contract certificate exists yet: install a new contract certificate using OEM provisioning cert. */
        ChrgM_Status.state = CertificateInstallationRes;
        sendCertificateInstallationReq(doc);
        break;
    case CHRGM_CertificateExpired:
        /* Expired contract certificate cannot be used for update authorization: install a new one. */
        ChrgM_Status.state = CertificateInstallationRes;
        sendCertificateInstallationReq(doc);
        break;
    case CHRGM_CertificateExpiredSoon:
        /* Contract certificate is still valid but near expiry: renew it before authorization/payment. */
        ChrgM_Status.state = CertificateUpdateRes;
        sendCertificateUpdateReq(doc);
        break;
    case CHRGM_Error_None:
        /* Contract certificate and private key are available and valid: continue normal PnC flow. */
        ChrgM_Status.state = PaymentDetailsRes;
        sendPaymentDetailsReq(doc);
        break;
    default:
        handleError(cert_status);
        return FAILED;
    }

    return Ok;
}
#endif

/* ========================================================================= */
template <typename T>
static ChrgM_ResponseCodeType handlePaymentServiceSelectionRes(T *doc)
{
    RESPONSE_CHECK(PaymentServiceSelectionRes);
    MHU_STOP_CHARGING();
    if(ChrgM_Status.payContract == 1){
#ifdef VF_USE_NX_SECURE
        ChrgM_ErrorHandlerType ret = handleCheckCertificate();
        return sendNextContractCertificateMessage(doc, ret);
#else
        handleError(CHRGM_FAILED);
        return FAILED;
#endif
    } else {
        
        /* [V2G2-509] */
        ChrgM_Status.state = AuthorizationRes;
        ChrgM_Status.OngoingTimer = _setTimer(V2G_EVCC_Ongoing_Timeout);
        sendAuthorizationReq(doc);
    }
 
    return Ok;
}
/* ========================================================================= */
template <typename T>
static ChrgM_ResponseCodeType handlePaymentDetailsRes(T *doc)
{
    RESPONSE_CHECK(PaymentDetailsRes);
    MHU_STOP_CHARGING();
 
    auto *res = &doc->V2G_Message.Body.PaymentDetailsRes;
    /*[V2G2-825]*/
    if constexpr (std::is_same<T, iso2_exiDocument>::value)
    {
        memcpy(ChrgM_Status.genChallenge, res->GenChallenge.bytes, iso2_genChallengeType_BYTES_SIZE);
        ULONG EVSETimeStamp = res->EVSETimeStamp;
    }

    ChrgM_Status.state = AuthorizationRes;
    ChrgM_Status.OngoingTimer = _setTimer(V2G_EVCC_Ongoing_Timeout);
    sendAuthorizationReq(doc);
 
    return Ok;
}
 
/* ========================================================================= */
auto *getAuthorizationResType(struct iso2_exiDocument *doc)
{
    return &doc->V2G_Message.Body.AuthorizationRes;
}
 
auto *getAuthorizationResType(struct din_exiDocument *doc)
{
    return &doc->V2G_Message.Body.ContractAuthenticationRes;
}
 
template <typename T>
static ChrgM_ResponseCodeType handleAuthorizationRes(T *doc)
{
    auto *res = getAuthorizationResType(doc);
    /* [V2G2-504] */
    ChrgM_Output.stEvseRespCode = res->ResponseCode;
    if (ChrgM_Output.stEvseRespCode >= (uint8_t)iso2_responseCodeType_FAILED)
    {
        handleError(CHRGM_FAILED);
        return FAILED;
    }
    MHU_STOP_CHARGING();
    auto processing = res->EVSEProcessing;
    ChrgM_Output.stEvseMsgProcn = processing;
    if (processing == (uint8_t)iso2_EVSEProcessingType_Finished) {
        /* [V2G2-505] */
        ChrgM_Status.state = ChargeParameterDiscoveryRes;
        ChrgM_Status.OngoingTimer = _setTimer(V2G_EVCC_Ongoing_Timeout);
        sendChargeParamDiscoveryReq(doc);
    } else {
        /* [V2G2-845] */
        sendAuthorizationReq(doc);
    }
    return Ok;
}
 
/* ========================================================================= */
template <typename T>
static ChrgM_ResponseCodeType handleChargeParameterDiscoveryRes(T *doc)
{
    /* [V2G2-504] */
    RESPONSE_CHECK(ChargeParameterDiscoveryRes);
    MHU_STOP_CHARGING();
    auto *res = &doc->V2G_Message.Body.ChargeParameterDiscoveryRes;
    auto processing = res->EVSEProcessing;
    ChrgM_Output.stEvseMsgProcn = processing;
    if (processing == (uint8_t)iso2_EVSEProcessingType_Finished)
    {
        if (res->AC_EVSEChargeParameter_isUsed) {
            auto *param = &res->AC_EVSEChargeParameter;
            ChrgM_Output.iEvseAcMaxLim =
                    ChrgMHlp_decodePhysical(&param->EVSEMaxCurrent);
            if constexpr (std::is_same<T, iso2_exiDocument>::value)
            {
                ChrgM_Output.uEvseAcNom =
                        ChrgMHlp_decodePhysical(&param->EVSENominalVoltage);
            }
            else if constexpr (std::is_same<T, din_exiDocument>::value)
            {
                ChrgM_Output.uEvseAcNom =
                        ChrgMHlp_decodePhysical(&param->EVSEMaxVoltage);
            }
            handleAcStatus(&param->AC_EVSEStatus);
        }
        if (res->DC_EVSEChargeParameter_isUsed) {
            auto *param = &res->DC_EVSEChargeParameter;
            ChrgM_Output.iEvseDcMaxLim =
                    ChrgMHlp_decodePhysical(&param->EVSEMaximumCurrentLimit);
            ChrgM_Output.iEvseDcMinLim =
                    ChrgMHlp_decodePhysical(&param->EVSEMinimumCurrentLimit);
            ChrgM_Output.uEvseDcMax =
                    ChrgMHlp_decodePhysical(&param->EVSEMaximumVoltageLimit);
            ChrgM_Output.uEvseDcMin =
                    ChrgMHlp_decodePhysical(&param->EVSEMinimumVoltageLimit);
            ChrgM_Output.iEvseDcPeakRpl =
                    ChrgMHlp_decodePhysical(&param->EVSEPeakCurrentRipple);
            if (param->EVSECurrentRegulationTolerance_isUsed)
            {
                ChrgM_Output.iEvseDcRglntolr =
                        ChrgMHlp_decodePhysical(&param->EVSECurrentRegulationTolerance);
            }
            ChrgM_Output.pwrEvseDcLim =
                    ChrgMHlp_decodePhysical(&param->EVSEMaximumPowerLimit);
            handleDcStatus(&param->DC_EVSEStatus);
        }
 
        if(res->SAScheduleList_isUsed){
      ChrgM_Status.SAScheduleID = res->SAScheduleList.SAScheduleTuple.array[0].SAScheduleTupleID;
    }
 
        if (_isAcMode()) {
            /* AC mode */
            ChrgM_Status.syncStateACHLC = true;
            ChrgM_Status.MsgTimer = _setTimer(10000);
        } else {
            /* DC mode */
            /* [V2G2-599] */
            ChrgM_Status.state = CableCheckRes;
            ChrgM_Status.CableCheckTimer = _setTimer(V2G_EVCC_CableCheck_Timeout);
            ChrgM_Status.MsgTimer = _setTimer(10000);
            if ((ChrgM_Status.CpState == CpStatus_C) || (ChrgM_Input.preCondCloseS2 == 1)) {
                sendCableCheckReq(doc);
            }
        }
    }
    else
    {
        /* [V2G2-685] */
        sendChargeParamDiscoveryReq(doc);
    }
    return Ok;
}
 
/* ========================================================================= */
template <typename T>
static ChrgM_ResponseCodeType handleCableCheckRes(T *doc)
{
    /* [V2G2-524] */
    RESPONSE_CHECK(CableCheckRes);
    MHU_STOP_CHARGING();
    auto *res = &doc->V2G_Message.Body.CableCheckRes;
    auto processing = res->EVSEProcessing;
    ChrgM_Output.stEvseMsgProcn = processing;
    handleDcStatus(&res->DC_EVSEStatus);
    if (processing == (uint8_t)iso2_EVSEProcessingType_Finished) {
        /* [V2G2-525] */
        ChrgM_Status.state = PreChargeRes;
        ChrgM_Status.PreChargeTimer = _setTimer(V2G_EVCC_PreCharge_Timeout);
        sendPrechargeReq(doc);
    } else {
        /* [V2G2-524] */
        ChrgM_Output.stEvseIso = iso2_isolationLevelType_Invalid;
        sendCableCheckReq(doc);
    }
    return Ok;
}
 
/* ========================================================================= */
template <typename T>
static ChrgM_ResponseCodeType handlePreChargeRes(T *doc)
{
    RESPONSE_CHECK(PreChargeRes);
    MHU_STOP_CHARGING();
    auto *res = &doc->V2G_Message.Body.PreChargeRes;
    float presentV = ChrgMHlp_decodePhysical(&res->EVSEPresentVoltage);
    float diff = fabs(presentV - ChrgM_Input.uDcEvChReq);
    handleDcStatus(&res->DC_EVSEStatus);
    if (diff < PRECHARGE_V_DIFF_THRESH) {
        ChrgM_Status.state = PowerDeliveryRes;
        sendPowerDeliveryReqStart(doc);
    } else {
        sendPrechargeReq(doc);
    }
    return Ok;
}
 
/* ========================================================================= */
template <typename T>
static ChrgM_ResponseCodeType handlePowerDeliveryRes(T *doc)
{
    RESPONSE_CHECK(PowerDeliveryRes);
    ChrgM_V2gStateType startState, endState;
    if (_isAcMode()) {
        startState = ChargingStatusRes;
        endState = SessionStopRes;
    } else {
        startState = CurrentDemandRes;
        endState = WeldingDetectionRes;
    }
 
    if (ChrgM_Status.chargeProgress) {
        ChrgM_Status.state = startState;
        if (_isAcMode()) {
            sendChargingStatusReq(doc);
        } else {
            sendCurrentDemandReq(doc);
        }
    } else {
        ChrgM_Status.state = endState;
        ChrgM_Status.MsgTimer = _setTimer(10000);
        if(endState == WeldingDetectionRes){
            ChrgM_Status.OngoingTimer = _setTimer(V2G_EVCC_Ongoing_Timeout);
            if (ChrgM_Status.CpState == CpStatus_B) {
                sendWeldingDetectionReq(doc);
            }
    } else {
            sendSessionStopReq(doc);
        }
    }
    return Ok;
}
 
/* ========================================================================= */
#define IS_SHUTDOWN(shutdown) ((shutdown) == 1)
#define CURR_THRESHOLD(current) ((current) < STOP_CURRENT_THRESHOLD)
#define IS_TIMER_ZERO(timer) ((timer) == 0)
template <typename T>
static ChrgM_ResponseCodeType handleCurrentDemandRes(T *doc)
{
    /* [V2G2-532] */
    RESPONSE_CHECK(CurrentDemandRes);
    auto *res = &doc->V2G_Message.Body.CurrentDemandRes;
    ChrgM_Output.iEvseDcAct = ChrgMHlp_decodePhysical(&res->EVSEPresentCurrent);
    ChrgM_Output.uEvseDcAct = ChrgMHlp_decodePhysical(&res->EVSEPresentVoltage);
    if (res->EVSEMaximumVoltageLimit_isUsed) {
        ChrgM_Output.uEvseDcMax =
                ChrgMHlp_decodePhysical(&res->EVSEMaximumVoltageLimit);
    }
    if (res->EVSEMaximumCurrentLimit_isUsed) {
        ChrgM_Output.iEvseDcMaxLim =
                ChrgMHlp_decodePhysical(&res->EVSEMaximumCurrentLimit);
    }
    if (res->EVSEMaximumPowerLimit_isUsed) {
        ChrgM_Output.pwrEvseDcLim =
                ChrgMHlp_decodePhysical(&res->EVSEMaximumPowerLimit);
    }
    handleDcStatus(&res->DC_EVSEStatus);
    if((CURR_THRESHOLD(ChrgM_Output.iEvseDcAct) && ((IS_SHUTDOWN(ChrgM_Status.bEmgcyShtdnPre)) || (ChrgM_Invalid_CPStatus(CpStatus_C))))
    || (IS_SHUTDOWN(ChrgM_Status.bEmgcyShtdnPre) && IS_TIMER_ZERO(ChrgM_Status.shutdownTimer))) {
        /*Emergency Stop*/
        ChrgM_Status.state = SessionStopRes;
        if (!CURR_THRESHOLD(ChrgM_Output.iEvseDcAct)) {
            /*Unlock the gun in case stop charging but current >5A*/
            ChrgM_Output.iEvseDcAct = 0;
        }
        handleError(CHRGM_Error_None);
    }
    else if ((res->DC_EVSEStatus.EVSEStatusCode ==
                        (uint8_t)iso2_DC_EVSEStatusCodeType_EVSE_Shutdown) ||
                        (res->DC_EVSEStatus.EVSENotification ==
                        (uint8_t)iso2_EVSENotificationType_StopCharging)) {
        /* [V2G2-527] */
        /* 61851-23 Figure CC.5: Normal shutdown by EVSE */
        /*Normal Stop*/
        ChrgM_Status.state = PowerDeliveryRes;
        sendPowerDeliveryReqStop(doc);
        ChrgM_Output.stEvseNotif = 1;
    }
    else if(IS_SHUTDOWN(ChrgM_Status.stChgEndPre) && (CURR_THRESHOLD(ChrgM_Output.iEvseDcAct) 
                    || IS_TIMER_ZERO(ChrgM_Status.shutdownTimer))){
        /* [V2G2-527] */
        /*Normal Stop*/
        ChrgM_Status.state = PowerDeliveryRes;
        if (!CURR_THRESHOLD(ChrgM_Output.iEvseDcAct)) {
            /*Unlock the gun in case stop charging but current >5A*/
            ChrgM_Output.iEvseDcAct = 0;
        }
        sendPowerDeliveryReqStop(doc);
    } else {
        //sendCurrentDemandReq(doc);
        ChrgM_Status.waitSend = 1;
        ChrgM_Status.waitTimer = _setTimer(100);
    }
    return Ok;
}
 
/* ========================================================================= */
template <typename T>
static ChrgM_ResponseCodeType handleChargingStatusRes(T *doc)
{
    RESPONSE_CHECK(ChargingStatusRes);
    auto *res = &doc->V2G_Message.Body.ChargingStatusRes;
    handleAcStatus(&res->AC_EVSEStatus);
    if (res->EVSEMaxCurrent_isUsed) {
        ChrgM_Output.iEvseAcMaxLim = ChrgMHlp_decodePhysical(&res->EVSEMaxCurrent);
    }
    if(IS_SHUTDOWN(ChrgM_Input.bEmgcyShtdn) || ChrgM_Invalid_CPStatus(CpStatus_C)) {
        /* Emergency Stop */
        handleError(CHRGM_Error_None);
    } else if (IS_SHUTDOWN(ChrgM_Input.stChgEnd) 
        || (res->AC_EVSEStatus.EVSENotification == (uint8_t)iso2_EVSENotificationType_StopCharging)) {
    /* Normal Stop*/
        if((res->AC_EVSEStatus.EVSENotification == (uint8_t)iso2_EVSENotificationType_StopCharging)){
            ChrgM_Output.stEvseNotif = 1;
        }
    ChrgM_Status.state = PowerDeliveryRes;
        sendPowerDeliveryReqStop(doc);
    } else {
        sendChargingStatusReq(doc);
    }
    return Ok;
}
 
/* ========================================================================= */
template <typename T>
static ChrgM_ResponseCodeType handleWeldingDetectionRes(T *doc)
{
    RESPONSE_CHECK(WeldingDetectionRes);
    auto *res = &doc->V2G_Message.Body.WeldingDetectionRes;
    handleDcStatus(&res->DC_EVSEStatus);
    ChrgM_Output.uEvseDcAct = ChrgMHlp_decodePhysical(&res->EVSEPresentVoltage);
    if(ChrgM_Input.bWldChkDone){
        ChrgM_Status.state = SessionStopRes;
        sendSessionStopReq(doc);
    } else {
        sendWeldingDetectionReq(doc);
    }
    return Ok;
}
 
/* ========================================================================= */
template <typename T>
static ChrgM_ResponseCodeType handleSessionStopRes(T *doc)
{
    RESPONSE_CHECK(SessionStopRes);
    ChrgM_Status.state = ChrgM_Idle;
    SoAd_CloseSoCon(_isTlsConnection() ? SoAdConf_Tls : SoAdConf_Tcp, false);
    return Ok;
}
 
/* ========================================================================= */
template <typename T>
static boolean validateSessionId(const T *doc)
{
    boolean ret = TRUE;
    if (doc->V2G_Message.Header.SessionID.bytesLen 
            != ChrgM_Status.sessionIDLen) {
        ret = FALSE;
    }
    if (memcmp(doc->V2G_Message.Header.SessionID.bytes,
                            ChrgM_Status.session, ChrgM_Status.sessionIDLen) != 0) {
        ret = FALSE;
    }
    if (ret == FALSE) {
        handleError(CHRGM_UnknownSession);
    }
    return ret;
}
 
template <typename T>
bool IsAuthorizationRes(T *body)
{
    return body->AuthorizationRes_isUsed;
}
 
template <>
bool IsAuthorizationRes(struct din_BodyType *body)
{
    return body->ContractAuthenticationRes_isUsed;
}
 
#define HANDLE_MSG(msg) if (body->msg##_isUsed) { return handle##msg(doc); }
template <typename T>
static ChrgM_ResponseCodeType decodeExi(T *doc)
{
    auto *body = &doc->V2G_Message.Body;
    if (body->SessionSetupRes_isUsed) {
        return handleSessionSetupRes(doc);
    }
    if (!validateSessionId(doc)) {
        return FAILED_UnknownSession;
    }
    HANDLE_MSG(ServiceDiscoveryRes);
    HANDLE_MSG(PaymentServiceSelectionRes);
    HANDLE_MSG(CertificateInstallationRes);
    HANDLE_MSG(CertificateUpdateRes);
    HANDLE_MSG(PaymentDetailsRes);
    if (IsAuthorizationRes(body)) {
        return handleAuthorizationRes(doc);
    }
    HANDLE_MSG(ChargeParameterDiscoveryRes);
    HANDLE_MSG(CableCheckRes);
    HANDLE_MSG(PreChargeRes);
    HANDLE_MSG(PowerDeliveryRes);
    HANDLE_MSG(CurrentDemandRes);
    HANDLE_MSG(ChargingStatusRes);
    HANDLE_MSG(WeldingDetectionRes);
    HANDLE_MSG(SessionStopRes);
    return FAILED;
}
 
/* ========================================================================= */
static boolean ChrgM_DecodeFrame(uint8_t *buf_recv, uint32_t *offset, uint8_t data)
{
    uint8_t ret = E_NOT_OK;
    switch (ChrgM_Status.dataField)
    {
    case PROTOCOL_VER:
    case PAYLOAD_TYPE2:
        if(data != 0x01) {
            ChrgM_Status.dataField = PROTOCOL_VER;
        } else {
            ChrgM_Status.dataField = ChrgM_DataField(ChrgM_Status.dataField + 1);
        }
        break;
    case INV_PROTOCOL_VER:
        if(data != 0xFE) {
            ChrgM_Status.dataField = PROTOCOL_VER;
        } else {
            ChrgM_Status.dataField = ChrgM_DataField(ChrgM_Status.dataField + 1);
        }
        break;
    case PAYLOAD_TYPE1:
        if(data != 0x80) {
            ChrgM_Status.dataField = PROTOCOL_VER;
        } else {
            ChrgM_Status.dataField = ChrgM_DataField(ChrgM_Status.dataField + 1);
            ChrgM_Status.tcpPayload = 0;
        }
        break;
    case PAYLOAD_LENG1:
    case PAYLOAD_LENG2:
    case PAYLOAD_LENG3:
    case PAYLOAD_LENG4:
        ChrgM_Status.tcpPayload |= (data << (8*(3 + PAYLOAD_LENG1 - ChrgM_Status.dataField)));
        ChrgM_Status.dataField = ChrgM_DataField(ChrgM_Status.dataField + 1);
        if(ChrgM_Status.tcpPayload > MAX_MESSAGEBUFFER) {
            ChrgM_Status.dataField = PROTOCOL_VER;
        }
        break;
    default:
        buf_recv[*offset] = data;
        (*offset)++;
        if(ChrgM_Status.tcpPayload == *offset) {
            ret = E_OK;
            *offset = 0;
        }
        break;
    }
    return ret;
}
 
template <typename T>
static void handleV2g(exi_bitstream_t *stream, T *doc)
{
    init_exiDocument(doc);
    if (decode_exiDocument(stream, doc) == 0) {
        decodeExi(doc);
    } else {
        handleError(CHRGM_MessageError);
    }
}
 
static void ChrgM_handleV2g(uint8* buffer, uint32_t size)
{
    boolean msg_success = E_NOT_OK;
    uint8 *cp = &buffer[0];
 
    while (size--)
    {
        msg_success = ChrgM_DecodeFrame(ChrgM_Status.buffer_recv, &ChrgM_Status.offset, *cp);
        cp++;
        if(msg_success == E_OK) {
            ChrgM_Status.dataField = PROTOCOL_VER;
            ChrgM_Status.offset = 0;
            msg_success = E_NOT_OK;
            exi_bitstream_t stream;
            exi_bitstream_init(&stream, ChrgM_Status.buffer_recv,
                                                ChrgM_Status.tcpPayload, 0, NULL);
            if (ChrgM_Status.state <= ChrgM_supportedAppProtocolRes) {
                handleAppHandshake(&stream);
            } else {
                if (ChrgM_Output.protocol == ISO15118_2) {
                    handleV2g(&stream, &ChrgM_Status.exiDoc.iso2);
                } else if (ChrgM_Output.protocol == DIN70121) {
                    handleV2g(&stream, &ChrgM_Status.exiDoc.din);
                }
            }
            memset(ChrgM_Status.buffer_recv, 0, MAX_MESSAGEBUFFER);
        }
    }
}
 
/* ========================================================================= */
static Std_ReturnType handleTimer(uint16 *timer, ChrgM_ErrorHandlerType error)
{
    boolean ret = E_OK;
    if (*timer == 0) {
        /* [V2G2-162] timeout */
        handleError(error);
        ret = E_NOT_OK;
    } else {
        *timer = *timer - 1;
    }
    return ret;
}
 
static Std_ReturnType handleCommnunicationSetup(void)
{
    return handleTimer(&ChrgM_Status.CommSetupTimer,
                                        V2G_EVCC_CommunicationSetupTimeout);
}
 
static Std_ReturnType handleMessageTimer(void)
{
    return handleTimer(&ChrgM_Status.MsgTimer, V2G_EVCC_MsgTimeout);
}
 
void ChrgM_SlacFinish(void)
{
    TcpIp_SockAddrInet6Type addr;
    addr.domain = TCPIP_AF_INET6;
    addr.port = V2G_UDP_SERVER_PORT;
    addr.addr[0] = 0xFF020000U;
    addr.addr[1] = 0U;
    addr.addr[2] = 0U;
    addr.addr[3] = 1U;
    SoAd_SetRemoteAddr(SoAdConf_Udp, (const TcpIp_SockAddrType *)&addr);
    ChrgM_Status.state = ChrgM_Sdp;
    ChrgM_Status.MsgTimer = 0;
    ChrgM_Status.CommSetupTimer = _setTimer(V2G_EVCC_CommunicationSetup_Timeout);
    ChrgM_Status.sdpCount = 0;
    memset(&ChrgM_Status.exiDoc, 0, sizeof(ChrgM_Status.exiDoc));
}
 
void ChrgM_SlacError(void)
{
    handleError(CHRGM_FAILED);
}
 
void ChrgM_RxIndication(PduIdType RxPduId, const PduInfoType *PduInfoPtr)
{
    switch (RxPduId) {
    case SoAdConf_Udp:
        ChrgM_handleSdp(PduInfoPtr->SduDataPtr, PduInfoPtr->SduLength);
        break;
    case SoAdConf_Tcp:
        ChrgM_handleV2g(PduInfoPtr->SduDataPtr, PduInfoPtr->SduLength);
        break;
    case SoAdConf_Tls:
        ChrgM_handleV2g(PduInfoPtr->SduDataPtr, PduInfoPtr->SduLength);
        break;
    default:
        break;
    }
}
 
static boolean checkStateChange(ChrgM_CpStatus expectStatus)
{
    return (ChrgM_Status.CpState != ChrgM_Status.CpStatePre)
        && (expectStatus == ChrgM_Status.CpState);
}
 
static void ChrgM_TriggerSlac(ChrgM_GunStatus gunStatus)
{
    switch(gunStatus){
    case GunStatus_locked:
        if((ChrgM_Status.stReadySlac == 1) && (ChrgM_Input.bBattSocValid == 1)){
            ChrgM_Status.state = ChrgM_Slac;
            ChrgM_Status.stReadySlac = 0;
            EVCCSlac_Start();
        }
        break;
    case GunStatus_unplugged:
        /*Clear V2G error when the gun is unplugged*/
        ChrgM_Status.shutdownTimer = 0xFFFF;
        ChrgM_Status.stChgEndPre = 0;
        ChrgM_Status.bEmgcyShtdnPre = 0;
        ChrgM_Status.error = CHRGM_Error_None;
        ChrgM_Status.seccSecurity = 0;
        ChrgM_Output.stEvse = iso2_DC_EVSEStatusCodeType_EVSE_NotReady;
        ChrgM_Output.stEvseRespCode = iso2_responseCodeType_OK;
        ChrgM_Output.stEvseChMode = 0xFF;
        ChrgM_Output.iEvseDcAct = 0;
        ChrgM_Output.iEvseDcPeakRpl = 0;
        ChrgM_Output.uEvseDcMin = 0;
    ChrgM_Output.stEvseNotif = iso2_EVSENotificationType_None;
        ChrgM_Output.stEvseIso = iso2_isolationLevelType_Invalid;
        ChrgM_Output.protocol = UNDEFINE;
        EVCCSlac_Init();
        break;
    default:
        break;
    }
}
 
extern uint8 SwAdapt_WakeUpSource_E;
void ChrgM_MainFunction(void)
{
    if ((ChrgM_Status.state > ChrgM_Slac)
            && ((ChrgM_Status.CpState == CpStatus_E)
                        || (ChrgM_Status.CpState == CpStatus_F))) {
        handleError(CHRGM_CpStateError);
    }
    if((ChrgM_Status.stChgEndPre == 0) && (ChrgM_Input.stChgEnd == 1)) {
        ChrgM_Status.stChgEndPre = ChrgM_Input.stChgEnd;
        ChrgM_Status.bEmgcyShtdnPre = ChrgM_Input.bEmgcyShtdn;
        if(ChrgM_Status.state == CurrentDemandRes) {
            ChrgM_Status.triggerStop = true;
        }
    }
    ChrgM_Status.CpState = (ChrgM_CpStatus)ChrgM_Input.stChPlgCP_2;
    ChrgM_Output.stV2G = ChrgM_Status.state;
    ChrgM_Output.stV2GErr = ChrgM_Status.error;
    switch (ChrgM_Status.state) {
    case ChrgM_Idle:
        if(!ChrgM_Status.wakeFirstCheck) {
            IoHwAb_Dio_Read(DioConf_DioChannel_S32K_PLUG_PRESENT_INT, (boolean *)&ChrgM_Status.plugInGun);
            if((ChrgM_Status.plugInGun == STD_HIGH && SwAdapt_WakeUpSource_E > GUN_WAKE_UP) || (ChrgM_Input.stChgEnd == 1)) { //Wakeup by Can or KL15
                ChrgM_Status.stCharging = 0;
            } else if(SwAdapt_WakeUpSource_E == GUN_WAKE_UP) { //Wakeup by plugGun
                ChrgM_Status.stCharging = 1;
            }
            ChrgM_Status.wakeFirstCheck = true;
        }
        if(ChrgM_Status.stReadySlac == 0) {
                ChrgM_Status.stCharging = 1;
        } else {
            IoHwAb_Dio_Read(DioConf_DioChannel_S32K_PLUG_PRESENT_INT, (boolean *)&ChrgM_Status.plugInGun);
            if(ChrgM_Status.plugInGun == STD_LOW) {
                ChrgM_Status.stReadySlac = 0;
            }
        }
        
        if(checkStateChange(CpStatus_B) && (ChrgM_Status.CpStatePre != CpStatus_C) && (ChrgM_Status.stCharging == 1)) {
            ChrgM_Status.stReadySlac = 1;
            ChrgM_Status.stCharging = 0;
            ChrgM_Status.error = CHRGM_Error_None;
        }
        ChrgM_TriggerSlac(ChrgM_Input.stChGun);
        break;
    case ChrgM_Slac:
        if((ChrgM_Status.CpState == CpStatus_E) || (ChrgM_Status.CpState == CpStatus_F)) {
            ChrgM_Status.state = ChrgM_Idle;
        }
        break;
    case ChrgM_Sdp:
        if ((SDP_MAX_RETRY * SDP_WAIT_TIME) >= V2G_EVCC_CommunicationSetup_Timeout) {
            /* [V2G2-020] */
            if (handleCommnunicationSetup() != E_OK) {
                break;
            }
        } else {
            handleCommnunicationSetup();
        }
        if (ChrgM_Status.MsgTimer == 0) {
            if (ChrgM_Status.sdpCount >= SDP_MAX_RETRY) {
                /* [V2G2-161] stop SDP */
                handleError(V2G_EVCC_CommunicationSetupTimeout);
            } else {
                /* [V2G2-157][V2G2-160] */
                ChrgM_Status.sdpCount++;
                sendSdp();
                ChrgM_Status.MsgTimer = _setTimer(SDP_WAIT_TIME);
            }
        } else {
            ChrgM_Status.MsgTimer--;
        }
        break;
    case ChrgM_Connect:
        handleCommnunicationSetup();
        break;
    case ChrgM_supportedAppProtocolRes:
    case SessionSetupRes:
        handleCommnunicationSetup();
        handleMessageTimer();
        break;
    case ServiceDiscoveryRes:
    case PaymentServiceSelectionRes:
    case CertificateUpdateRes:
    case PowerDeliveryRes:
    case SessionStopRes:
    case ChargingStatusRes:
    case CertificateInstallationRes:
    case PaymentDetailsRes:
        handleMessageTimer();
        break;
    case CurrentDemandRes:
        if((ChrgM_Status.shutdownTimer > 0) && (ChrgM_Status.shutdownTimer != 0xFFFF)){
            ChrgM_Status.shutdownTimer--;
        }
        if(ChrgM_Status.waitSend) {
            if(ChrgM_Status.waitTimer == 0) {
                SEND_REQ_MSG(CurrentDemandReq);
                ChrgM_Status.waitSend = 0;
            } else {
                ChrgM_Status.waitTimer--;
            }
        } else {
            handleMessageTimer();
        }
        break;
    case AuthorizationRes:
        handleTimer(&ChrgM_Status.OngoingTimer, V2G_EVCC_OngoingTimeout);
        handleMessageTimer();
        break;
    case ChargeParameterDiscoveryRes:
        if((ChrgM_Status.syncStateACHLC == true) && (ChrgM_Input.preCondCloseS2 == 1)) {
            ChrgM_Status.state = PowerDeliveryRes;
            SEND_REQ_MSG(PowerDeliveryReqStart);
            ChrgM_Status.syncStateACHLC = false;
        }
        handleTimer(&ChrgM_Status.OngoingTimer, V2G_EVCC_OngoingTimeout);
        handleMessageTimer();
        break;
    case PreChargeRes:
        handleTimer(&ChrgM_Status.PreChargeTimer, V2G_EVCC_PrechargeTimeout);
        handleMessageTimer();
        break;
    case CableCheckRes:
        if (checkStateChange(CpStatus_C)) {
            /* Make sure CP is in C state */
            SEND_REQ_MSG(CableCheckReq);
        }
        handleTimer(&ChrgM_Status.CableCheckTimer, V2G_EVCC_CableCheckTimeout);
        handleMessageTimer();
        break;
    case WeldingDetectionRes:
        if (checkStateChange(CpStatus_B)) {
            /* Make sure CP is in B state */
            SEND_REQ_MSG(WeldingDetectionReq);
        }
        handleTimer(&ChrgM_Status.OngoingTimer, V2G_EVCC_OngoingTimeout);
        handleMessageTimer();
        break;
    default:
        break;
    }
    ChrgM_Status.CpStatePre = ChrgM_Status.CpState;
}
