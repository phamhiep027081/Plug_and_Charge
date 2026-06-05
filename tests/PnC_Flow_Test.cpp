#include <cassert>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr std::uint32_t kSecondsPerDay = 86400U;
constexpr std::uint32_t kCertUpdateWindow = 10U * kSecondsPerDay;

enum ChrgM_ErrorHandlerType {
    CHRGM_Error_None,
    CHRGM_FAILED,
    CHRGM_NoCertificateAvailable,
    CHRGM_CertificateExpired,
    CHRGM_CertificateExpiredSoon,
};

enum ChrgM_V2gStateType {
    PaymentServiceSelectionRes,
    CertificateInstallationRes,
    CertificateUpdateRes,
    PaymentDetailsRes,
    AuthorizationRes,
};

struct SimulatedCert {
    bool has_contract_cert;
    bool has_private_key;
    bool has_emaid;
    std::uint32_t not_after_unix;
};

struct FlowContext {
    bool pay_contract;
    ChrgM_V2gStateType state;
    std::vector<std::string> calls;
};

struct TestReportRow {
    std::string name;
    std::string input;
    std::vector<std::string> expected_calls;
    std::vector<std::string> actual_calls;
    ChrgM_V2gStateType expected_state;
    ChrgM_V2gStateType actual_state;
    bool passed;
};

bool nx_secure_x509_expiration_check(const SimulatedCert& cert, std::uint32_t unix_time)
{
    return unix_time >= cert.not_after_unix;
}

ChrgM_ErrorHandlerType handleCheckCertificate(const SimulatedCert& cert, std::uint32_t now_unix)
{
    if (!cert.has_contract_cert || !cert.has_private_key || !cert.has_emaid) {
        return CHRGM_NoCertificateAvailable;
    }

    if (nx_secure_x509_expiration_check(cert, now_unix)) {
        return CHRGM_CertificateExpired;
    }

    if (nx_secure_x509_expiration_check(cert, now_unix + kCertUpdateWindow)) {
        return CHRGM_CertificateExpiredSoon;
    }

    return CHRGM_Error_None;
}

void sendCertificateInstallationReq(FlowContext& ctx)
{
    ctx.state = CertificateInstallationRes;
    ctx.calls.push_back("CertificateInstallationReq");
}

void sendCertificateUpdateReq(FlowContext& ctx)
{
    ctx.state = CertificateUpdateRes;
    ctx.calls.push_back("CertificateUpdateReq");
}

void sendPaymentDetailsReq(FlowContext& ctx)
{
    ctx.state = PaymentDetailsRes;
    ctx.calls.push_back("PaymentDetailsReq");
}

void sendAuthorizationReq(FlowContext& ctx)
{
    ctx.state = AuthorizationRes;
    ctx.calls.push_back("AuthorizationReq");
}

ChrgM_ErrorHandlerType sendNextContractCertificateMessage(FlowContext& ctx,
                                                          ChrgM_ErrorHandlerType cert_status)
{
    switch (cert_status) {
    case CHRGM_NoCertificateAvailable:
        sendCertificateInstallationReq(ctx);
        return CHRGM_Error_None;
    case CHRGM_CertificateExpired:
        sendCertificateInstallationReq(ctx);
        return CHRGM_Error_None;
    case CHRGM_CertificateExpiredSoon:
        sendCertificateUpdateReq(ctx);
        return CHRGM_Error_None;
    case CHRGM_Error_None:
        sendPaymentDetailsReq(ctx);
        return CHRGM_Error_None;
    default:
        return CHRGM_FAILED;
    }
}

ChrgM_ErrorHandlerType handlePaymentServiceSelectionRes(FlowContext& ctx,
                                                        const SimulatedCert& cert,
                                                        std::uint32_t now_unix)
{
    if (ctx.pay_contract) {
        return sendNextContractCertificateMessage(ctx, handleCheckCertificate(cert, now_unix));
    }

    sendAuthorizationReq(ctx);
    return CHRGM_Error_None;
}

void handleCertificateInstallationRes(FlowContext& ctx)
{
    assert(ctx.state == CertificateInstallationRes);
    sendPaymentDetailsReq(ctx);
}

void handleCertificateUpdateRes(FlowContext& ctx)
{
    assert(ctx.state == CertificateUpdateRes);
    sendPaymentDetailsReq(ctx);
}

void handlePaymentDetailsRes(FlowContext& ctx)
{
    assert(ctx.state == PaymentDetailsRes);
    sendAuthorizationReq(ctx);
}

void assertOnlyCall(const FlowContext& ctx, const std::string& call)
{
    assert(ctx.calls.size() == 1);
    assert(ctx.calls[0] == call);
}

const char* stateName(ChrgM_V2gStateType state)
{
    switch (state) {
    case PaymentServiceSelectionRes:
        return "PaymentServiceSelectionRes";
    case CertificateInstallationRes:
        return "CertificateInstallationRes";
    case CertificateUpdateRes:
        return "CertificateUpdateRes";
    case PaymentDetailsRes:
        return "PaymentDetailsRes";
    case AuthorizationRes:
        return "AuthorizationRes";
    default:
        return "Unknown";
    }
}

std::string yesNo(bool value)
{
    return value ? "yes" : "no";
}

std::string joinCalls(const std::vector<std::string>& calls)
{
    if (calls.empty()) {
        return "(none)";
    }

    std::ostringstream out;
    for (std::size_t i = 0; i < calls.size(); i++) {
        if (i != 0) {
            out << " -> ";
        }
        out << calls[i];
    }
    return out.str();
}

std::string htmlEscape(const std::string& text)
{
    std::string escaped;
    for (char ch : text) {
        switch (ch) {
        case '&':
            escaped += "&amp;";
            break;
        case '<':
            escaped += "&lt;";
            break;
        case '>':
            escaped += "&gt;";
            break;
        case '"':
            escaped += "&quot;";
            break;
        default:
            escaped += ch;
            break;
        }
    }
    return escaped;
}

std::string describeCert(const SimulatedCert& cert, std::uint32_t now_unix, bool pay_contract)
{
    std::ostringstream out;
    out << "payContract=" << yesNo(pay_contract)
        << ", hasCert=" << yesNo(cert.has_contract_cert)
        << ", hasPrivateKey=" << yesNo(cert.has_private_key)
        << ", hasEMAID=" << yesNo(cert.has_emaid)
        << ", now=" << now_unix
        << ", notAfter=" << cert.not_after_unix
        << ", updateWindowDays=" << (kCertUpdateWindow / kSecondsPerDay);
    return out.str();
}

TestReportRow runReportCase(const std::string& name,
                            const SimulatedCert& cert,
                            bool pay_contract,
                            std::uint32_t now_unix,
                            const std::vector<std::string>& expected_calls,
                            ChrgM_V2gStateType expected_state,
                            bool finish_certificate_management,
                            bool finish_payment_details)
{
    FlowContext ctx{pay_contract, PaymentServiceSelectionRes, {}};
    handlePaymentServiceSelectionRes(ctx, cert, now_unix);

    if (finish_certificate_management && ctx.state == CertificateInstallationRes) {
        handleCertificateInstallationRes(ctx);
    } else if (finish_certificate_management && ctx.state == CertificateUpdateRes) {
        handleCertificateUpdateRes(ctx);
    }

    if (finish_payment_details && ctx.state == PaymentDetailsRes) {
        handlePaymentDetailsRes(ctx);
    }

    bool passed = (ctx.calls == expected_calls) && (ctx.state == expected_state);
    return TestReportRow{
        name,
        describeCert(cert, now_unix, pay_contract),
        expected_calls,
        ctx.calls,
        expected_state,
        ctx.state,
        passed,
    };
}

void writeHtmlReport(const std::vector<TestReportRow>& rows, const std::string& path)
{
    std::ofstream html(path);
    assert(html.is_open());

    std::size_t passed_count = 0;
    for (const auto& row : rows) {
        if (row.passed) {
            passed_count++;
        }
    }

    html << "<!doctype html>\n<html><head><meta charset=\"utf-8\">\n"
         << "<title>PnC Flow Test Report</title>\n"
         << "<style>"
         << "body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2933;background:#f7f9fb;}"
         << "h1{margin-bottom:4px;} .summary{margin:0 0 18px;color:#52606d;}"
         << "table{border-collapse:collapse;width:100%;background:white;border:1px solid #d9e2ec;}"
         << "th,td{border:1px solid #d9e2ec;padding:10px;text-align:left;vertical-align:top;font-size:14px;}"
         << "th{background:#e6f6ff;color:#102a43;} .pass{color:#0b6b3a;font-weight:700;}"
         << ".fail{color:#b42318;font-weight:700;} code{white-space:normal;color:#243b53;}"
         << "</style></head><body>\n"
         << "<h1>PnC Flow Test Report</h1>\n"
         << "<p class=\"summary\">Passed " << passed_count << " / " << rows.size()
         << " cases. Certificate update window: " << (kCertUpdateWindow / kSecondsPerDay)
         << " days.</p>\n"
         << "<table><thead><tr>"
         << "<th>Case</th><th>Input</th><th>Expected Flow</th><th>Actual Flow</th>"
         << "<th>Expected State</th><th>Actual State</th><th>Result</th>"
         << "</tr></thead><tbody>\n";

    for (const auto& row : rows) {
        html << "<tr>"
             << "<td>" << htmlEscape(row.name) << "</td>"
             << "<td><code>" << htmlEscape(row.input) << "</code></td>"
             << "<td>" << htmlEscape(joinCalls(row.expected_calls)) << "</td>"
             << "<td>" << htmlEscape(joinCalls(row.actual_calls)) << "</td>"
             << "<td>" << stateName(row.expected_state) << "</td>"
             << "<td>" << stateName(row.actual_state) << "</td>"
             << "<td class=\"" << (row.passed ? "pass" : "fail") << "\">"
             << (row.passed ? "PASS" : "FAIL") << "</td>"
             << "</tr>\n";
    }

    html << "</tbody></table>\n</body></html>\n";
}

void generateReport()
{
    constexpr std::uint32_t now = 1700000000U;
    std::vector<TestReportRow> rows;

    rows.push_back(runReportCase(
        "No cert/private key/eMAID -> install",
        SimulatedCert{false, false, false, now + 30U * kSecondsPerDay},
        true, now, {"CertificateInstallationReq"}, CertificateInstallationRes, false, false));
    rows.push_back(runReportCase(
        "Expired contract cert -> install",
        SimulatedCert{true, true, true, now - 1U},
        true, now, {"CertificateInstallationReq"}, CertificateInstallationRes, false, false));
    rows.push_back(runReportCase(
        "Cert expires within 10 days -> update",
        SimulatedCert{true, true, true, now + 5U * kSecondsPerDay},
        true, now, {"CertificateUpdateReq"}, CertificateUpdateRes, false, false));
    rows.push_back(runReportCase(
        "Valid cert beyond update window -> payment details",
        SimulatedCert{true, true, true, now + 30U * kSecondsPerDay},
        true, now, {"PaymentDetailsReq"}, PaymentDetailsRes, false, false));
    rows.push_back(runReportCase(
        "External payment -> authorization",
        SimulatedCert{false, false, false, now},
        false, now, {"AuthorizationReq"}, AuthorizationRes, false, false));
    rows.push_back(runReportCase(
        "Installation success path",
        SimulatedCert{false, false, false, now},
        true, now,
        {"CertificateInstallationReq", "PaymentDetailsReq", "AuthorizationReq"},
        AuthorizationRes, true, true));
    rows.push_back(runReportCase(
        "Update success path",
        SimulatedCert{true, true, true, now + 5U * kSecondsPerDay},
        true, now,
        {"CertificateUpdateReq", "PaymentDetailsReq", "AuthorizationReq"},
        AuthorizationRes, true, true));

    writeHtmlReport(rows, "tests/PnC_Flow_Report.html");
}

void test_no_certificate_routes_to_installation()
{
    constexpr std::uint32_t now = 1700000000U;
    SimulatedCert cert{false, false, false, now + 30U * kSecondsPerDay};
    FlowContext ctx{true, PaymentServiceSelectionRes, {}};

    assert(handlePaymentServiceSelectionRes(ctx, cert, now) == CHRGM_Error_None);
    assert(ctx.state == CertificateInstallationRes);
    assertOnlyCall(ctx, "CertificateInstallationReq");
}

void test_expired_certificate_routes_to_installation()
{
    constexpr std::uint32_t now = 1700000000U;
    SimulatedCert cert{true, true, true, now - 1U};
    FlowContext ctx{true, PaymentServiceSelectionRes, {}};

    assert(handlePaymentServiceSelectionRes(ctx, cert, now) == CHRGM_Error_None);
    assert(ctx.state == CertificateInstallationRes);
    assertOnlyCall(ctx, "CertificateInstallationReq");
}

void test_certificate_expiring_soon_routes_to_update()
{
    constexpr std::uint32_t now = 1700000000U;
    SimulatedCert cert{true, true, true, now + 5U * kSecondsPerDay};
    FlowContext ctx{true, PaymentServiceSelectionRes, {}};

    assert(handlePaymentServiceSelectionRes(ctx, cert, now) == CHRGM_Error_None);
    assert(ctx.state == CertificateUpdateRes);
    assertOnlyCall(ctx, "CertificateUpdateReq");
}

void test_valid_certificate_routes_to_payment_details()
{
    constexpr std::uint32_t now = 1700000000U;
    SimulatedCert cert{true, true, true, now + 30U * kSecondsPerDay};
    FlowContext ctx{true, PaymentServiceSelectionRes, {}};

    assert(handlePaymentServiceSelectionRes(ctx, cert, now) == CHRGM_Error_None);
    assert(ctx.state == PaymentDetailsRes);
    assertOnlyCall(ctx, "PaymentDetailsReq");
}

void test_external_payment_skips_certificate_management()
{
    constexpr std::uint32_t now = 1700000000U;
    SimulatedCert cert{false, false, false, now};
    FlowContext ctx{false, PaymentServiceSelectionRes, {}};

    assert(handlePaymentServiceSelectionRes(ctx, cert, now) == CHRGM_Error_None);
    assert(ctx.state == AuthorizationRes);
    assertOnlyCall(ctx, "AuthorizationReq");
}

void test_installation_success_continues_to_authorization()
{
    constexpr std::uint32_t now = 1700000000U;
    SimulatedCert cert{false, false, false, now};
    FlowContext ctx{true, PaymentServiceSelectionRes, {}};

    handlePaymentServiceSelectionRes(ctx, cert, now);
    handleCertificateInstallationRes(ctx);
    handlePaymentDetailsRes(ctx);

    assert((ctx.calls == std::vector<std::string>{
        "CertificateInstallationReq",
        "PaymentDetailsReq",
        "AuthorizationReq",
    }));
    assert(ctx.state == AuthorizationRes);
}

void test_update_success_continues_to_authorization()
{
    constexpr std::uint32_t now = 1700000000U;
    SimulatedCert cert{true, true, true, now + 5U * kSecondsPerDay};
    FlowContext ctx{true, PaymentServiceSelectionRes, {}};

    handlePaymentServiceSelectionRes(ctx, cert, now);
    handleCertificateUpdateRes(ctx);
    handlePaymentDetailsRes(ctx);

    assert((ctx.calls == std::vector<std::string>{
        "CertificateUpdateReq",
        "PaymentDetailsReq",
        "AuthorizationReq",
    }));
    assert(ctx.state == AuthorizationRes);
}

} // namespace

int main()
{
    test_no_certificate_routes_to_installation();
    test_expired_certificate_routes_to_installation();
    test_certificate_expiring_soon_routes_to_update();
    test_valid_certificate_routes_to_payment_details();
    test_external_payment_skips_certificate_management();
    test_installation_success_continues_to_authorization();
    test_update_success_continues_to_authorization();
    generateReport();

    std::cout << "PnC flow tests passed\n";
    std::cout << "HTML report: tests/PnC_Flow_Report.html\n";
    return 0;
}
