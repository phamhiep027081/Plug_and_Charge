#include <cassert>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr std::uint32_t kSecondsPerDay = 86400U;
constexpr std::uint32_t kUpdateWindow = 10U * kSecondsPerDay;
constexpr std::size_t kMaxCertSize = 512U;
constexpr std::size_t kMaxKeySize = 128U;
constexpr std::size_t kMaxEmaidSize = 32U;
constexpr std::size_t kMaxRootCount = 5U;

enum class NextMessage {
    CertificateInstallationReq,
    CertificateUpdateReq,
    PaymentDetailsReq,
    Failed,
};

struct RamBlob {
    std::uint8_t bytes[kMaxCertSize]{};
    std::size_t len{};
};

struct RamKey {
    std::uint8_t bytes[kMaxKeySize]{};
    std::size_t len{};
    bool non_exportable_handle{};
};

struct RamCertificate {
    RamBlob der{};
    RamKey private_key{};
    std::uint32_t not_after_unix{};
    std::string issuer_name{};
    std::uint32_t serial{};
};

struct RamStore {
    RamCertificate oem_provisioning{};
    RamCertificate v2g_roots[kMaxRootCount]{};
    std::size_t root_count{};
    RamCertificate contract{};
    RamCertificate mo_sub_ca{};
    RamCertificate sa_provisioning{};
    char emaid[kMaxEmaidSize]{};
    std::size_t emaid_len{};
    std::uint16_t retry_counter{};
};

struct InstallationReq {
    RamBlob oem_provisioning_cert{};
    std::size_t root_count{};
};

struct UpdateReq {
    RamBlob current_contract_cert{};
    char emaid[kMaxEmaidSize]{};
    std::size_t emaid_len{};
    std::size_t root_count{};
};

struct CertificateResponse {
    RamCertificate contract{};
    RamCertificate mo_sub_ca{};
    RamCertificate sa_provisioning{};
    RamBlob encrypted_private_key{};
    RamBlob dh_public_key{};
    char emaid[kMaxEmaidSize]{};
    std::size_t emaid_len{};
    bool retry_counter_used{};
    std::uint16_t retry_counter{};
};

struct ReportRow {
    std::string name;
    bool passed;
    std::string detail;
};

std::vector<ReportRow> g_report;

void fillBlob(RamBlob& blob, std::uint8_t seed, std::size_t len)
{
    assert(len <= sizeof(blob.bytes));
    blob.len = len;
    for (std::size_t i = 0; i < len; i++) {
        blob.bytes[i] = static_cast<std::uint8_t>(seed + i);
    }
}

void fillKey(RamKey& key, std::uint8_t seed, std::size_t len, bool non_exportable)
{
    assert(len <= sizeof(key.bytes));
    key.len = len;
    key.non_exportable_handle = non_exportable;
    for (std::size_t i = 0; i < len; i++) {
        key.bytes[i] = static_cast<std::uint8_t>(seed ^ i);
    }
}

bool sameBlob(const RamBlob& a, const RamBlob& b)
{
    return (a.len == b.len) && (std::memcmp(a.bytes, b.bytes, a.len) == 0);
}

bool certExpired(const RamCertificate& cert, std::uint32_t now_unix)
{
    return cert.der.len == 0 || now_unix >= cert.not_after_unix;
}

bool certExpiresSoon(const RamCertificate& cert, std::uint32_t now_unix)
{
    return !certExpired(cert, now_unix) && ((now_unix + kUpdateWindow) >= cert.not_after_unix);
}

bool hasContractCredential(const RamStore& store)
{
    return store.contract.der.len != 0 && store.contract.private_key.len != 0 && store.emaid_len != 0;
}

NextMessage selectNextMessage(const RamStore& store,
                              std::uint32_t now_unix,
                              bool contract_payment_selected,
                              bool contract_certificate_service_available)
{
    if (!contract_payment_selected) {
        return NextMessage::PaymentDetailsReq;
    }
    if (!contract_certificate_service_available) {
        return NextMessage::Failed;
    }
    if (!hasContractCredential(store) || certExpired(store.contract, now_unix)) {
        return NextMessage::CertificateInstallationReq;
    }
    if (certExpiresSoon(store.contract, now_unix)) {
        return NextMessage::CertificateUpdateReq;
    }
    return NextMessage::PaymentDetailsReq;
}

bool buildCertificateInstallationReq(const RamStore& store, InstallationReq& req)
{
    if (store.oem_provisioning.der.len == 0 || store.root_count == 0) {
        return false;
    }
    req.oem_provisioning_cert = store.oem_provisioning.der;
    req.root_count = store.root_count;
    return true;
}

bool buildCertificateUpdateReq(const RamStore& store, UpdateReq& req)
{
    if (!hasContractCredential(store) || store.root_count == 0) {
        return false;
    }
    req.current_contract_cert = store.contract.der;
    req.emaid_len = store.emaid_len;
    std::memcpy(req.emaid, store.emaid, store.emaid_len);
    req.root_count = store.root_count;
    return true;
}

bool fakeDecryptContractPrivateKey(const CertificateResponse& res, RamKey& key_out)
{
    if (res.encrypted_private_key.len <= 16 || res.dh_public_key.len == 0) {
        return false;
    }
    std::size_t key_len = res.encrypted_private_key.len - 16;
    if (key_len > sizeof(key_out.bytes)) {
        return false;
    }
    key_out.len = key_len;
    key_out.non_exportable_handle = true;
    std::memcpy(key_out.bytes, &res.encrypted_private_key.bytes[16], key_len);
    return true;
}

bool processCertificateInstallationRes(RamStore& store, const CertificateResponse& res)
{
    RamKey decrypted_key{};
    if (res.contract.der.len == 0 || res.sa_provisioning.der.len == 0 ||
            res.emaid_len == 0 || !fakeDecryptContractPrivateKey(res, decrypted_key)) {
        return false;
    }
    store.contract = res.contract;
    store.contract.private_key = decrypted_key;
    store.mo_sub_ca = res.mo_sub_ca;
    store.sa_provisioning = res.sa_provisioning;
    store.emaid_len = res.emaid_len;
    std::memcpy(store.emaid, res.emaid, res.emaid_len);
    return true;
}

bool processCertificateUpdateRes(RamStore& store, const CertificateResponse& res)
{
    RamStore candidate = store;
    if (!processCertificateInstallationRes(candidate, res)) {
        return false;
    }
    if (res.retry_counter_used) {
        candidate.retry_counter = res.retry_counter;
    }
    store = candidate;
    return true;
}

RamStore makeProvisionedStore(std::uint32_t now_unix)
{
    RamStore store{};
    fillBlob(store.oem_provisioning.der, 0x10, 64);
    fillKey(store.oem_provisioning.private_key, 0xA0, 32, true);
    store.oem_provisioning.not_after_unix = now_unix + 365U * kSecondsPerDay;
    store.oem_provisioning.issuer_name = "OEM Provisioning CA";
    store.oem_provisioning.serial = 1001;

    store.root_count = 2;
    for (std::size_t i = 0; i < store.root_count; i++) {
        fillBlob(store.v2g_roots[i].der, static_cast<std::uint8_t>(0x20 + i), 72);
        store.v2g_roots[i].not_after_unix = now_unix + 10U * 365U * kSecondsPerDay;
        store.v2g_roots[i].issuer_name = "V2G Root CA";
        store.v2g_roots[i].serial = static_cast<std::uint32_t>(2000 + i);
    }
    return store;
}

CertificateResponse makeCertificateResponse(std::uint32_t now_unix, const char* emaid, std::uint8_t seed)
{
    CertificateResponse res{};
    fillBlob(res.contract.der, seed, 96);
    res.contract.not_after_unix = now_unix + 365U * kSecondsPerDay;
    res.contract.issuer_name = "MO Sub-CA";
    res.contract.serial = seed;
    fillBlob(res.mo_sub_ca.der, static_cast<std::uint8_t>(seed + 1U), 80);
    fillBlob(res.sa_provisioning.der, static_cast<std::uint8_t>(seed + 2U), 80);
    fillBlob(res.dh_public_key, static_cast<std::uint8_t>(seed + 3U), 65);
    fillBlob(res.encrypted_private_key, static_cast<std::uint8_t>(seed + 4U), 16 + 48);
    res.emaid_len = std::strlen(emaid);
    std::memcpy(res.emaid, emaid, res.emaid_len);
    return res;
}

void record(const std::string& name, bool passed, const std::string& detail)
{
    g_report.push_back({name, passed, detail});
    assert(passed);
}

const char* messageName(NextMessage msg)
{
    switch (msg) {
    case NextMessage::CertificateInstallationReq:
        return "CertificateInstallationReq";
    case NextMessage::CertificateUpdateReq:
        return "CertificateUpdateReq";
    case NextMessage::PaymentDetailsReq:
        return "PaymentDetailsReq";
    case NextMessage::Failed:
        return "Failed";
    default:
        return "Unknown";
    }
}

std::string htmlEscape(const std::string& text)
{
    std::string escaped;
    for (char ch : text) {
        switch (ch) {
        case '&': escaped += "&amp;"; break;
        case '<': escaped += "&lt;"; break;
        case '>': escaped += "&gt;"; break;
        case '"': escaped += "&quot;"; break;
        default: escaped += ch; break;
        }
    }
    return escaped;
}

void writeReport()
{
    std::ofstream report("tests/PnC_Ram_Regression_Report.html", std::ios::binary);
    report << "<!doctype html><html><head><meta charset=\"utf-8\"><title>PnC RAM Regression</title>"
           << "<style>body{font-family:Arial,sans-serif;margin:24px;color:#20242a}"
           << "table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccd2da;padding:8px;text-align:left}"
           << ".pass{color:#087443;font-weight:700}.fail{color:#b42318;font-weight:700}</style></head><body>"
           << "<h1>PnC RAM Regression</h1>"
           << "<p>Regression runs entirely on RAM-backed simulated cert/key stores, matching the NetX Secure test style.</p>"
           << "<table><thead><tr><th>Case</th><th>Status</th><th>Detail</th></tr></thead><tbody>";
    for (const auto& row : g_report) {
        report << "<tr><td>" << htmlEscape(row.name) << "</td><td class=\""
               << (row.passed ? "pass\">PASS" : "fail\">FAIL") << "</td><td>"
               << htmlEscape(row.detail) << "</td></tr>";
    }
    report << "</tbody></table></body></html>";
}

void runCases()
{
    constexpr std::uint32_t now = 1700000000U;

    {
        RamStore store = makeProvisionedStore(now);
        NextMessage msg = selectNextMessage(store, now, true, true);
        InstallationReq req{};
        bool built = buildCertificateInstallationReq(store, req);
        record("No contract certificate installs", msg == NextMessage::CertificateInstallationReq && built,
               std::string("next=") + messageName(msg) + ", roots=" + std::to_string(req.root_count));
    }
    {
        RamStore store = makeProvisionedStore(now);
        CertificateResponse res = makeCertificateResponse(now, "DE*PNC*EMAID01", 0x30);
        assert(processCertificateInstallationRes(store, res));
        store.contract.not_after_unix = now - 1U;
        NextMessage msg = selectNextMessage(store, now, true, true);
        record("Expired contract reinstalls", msg == NextMessage::CertificateInstallationReq,
               std::string("next=") + messageName(msg));
    }
    {
        RamStore store = makeProvisionedStore(now);
        CertificateResponse res = makeCertificateResponse(now, "DE*PNC*EMAID02", 0x40);
        assert(processCertificateInstallationRes(store, res));
        store.contract.not_after_unix = now + 2U * kSecondsPerDay;
        NextMessage msg = selectNextMessage(store, now, true, true);
        UpdateReq req{};
        bool built = buildCertificateUpdateReq(store, req);
        record("Soon-to-expire contract updates", msg == NextMessage::CertificateUpdateReq && built,
               std::string("next=") + messageName(msg) + ", emaidLen=" + std::to_string(req.emaid_len));
    }
    {
        RamStore store = makeProvisionedStore(now);
        CertificateResponse res = makeCertificateResponse(now, "DE*PNC*EMAID03", 0x50);
        assert(processCertificateInstallationRes(store, res));
        store.contract.not_after_unix = now + 90U * kSecondsPerDay;
        NextMessage msg = selectNextMessage(store, now, true, true);
        record("Valid contract continues payment details", msg == NextMessage::PaymentDetailsReq,
               std::string("next=") + messageName(msg));
    }
    {
        RamStore store = makeProvisionedStore(now);
        CertificateResponse res = makeCertificateResponse(now, "DE*PNC*INSTALL", 0x60);
        bool ok = processCertificateInstallationRes(store, res);
        record("Installation response stores RAM material",
               ok && store.contract.der.len != 0 && store.contract.private_key.non_exportable_handle &&
                   store.mo_sub_ca.der.len != 0 && store.sa_provisioning.der.len != 0 &&
                   store.emaid_len == std::strlen("DE*PNC*INSTALL"),
               "contract key stored as non-exportable RAM handle");
    }
    {
        RamStore store = makeProvisionedStore(now);
        CertificateResponse first = makeCertificateResponse(now, "DE*PNC*OLD", 0x70);
        assert(processCertificateInstallationRes(store, first));
        CertificateResponse next = makeCertificateResponse(now, "DE*PNC*NEW", 0x80);
        next.retry_counter_used = true;
        next.retry_counter = 3;
        bool ok = processCertificateUpdateRes(store, next);
        record("Update response atomically replaces contract",
               ok && sameBlob(store.contract.der, next.contract.der) && store.retry_counter == 3 &&
                   store.emaid_len == std::strlen("DE*PNC*NEW"),
               "new contract/eMAID active in RAM");
    }
    {
        RamStore store = makeProvisionedStore(now);
        NextMessage msg = selectNextMessage(store, now, true, false);
        record("Missing ContractCertificate service blocks PnC management", msg == NextMessage::Failed,
               std::string("next=") + messageName(msg));
    }
}

} // namespace

int main()
{
    runCases();
    writeReport();
    std::cout << "PnC RAM regression passed\n";
    std::cout << "HTML report: tests/PnC_Ram_Regression_Report.html\n";
    return 0;
}
