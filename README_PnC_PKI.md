# PnC PKI test certificates

README này hướng dẫn tạo và dùng bộ chứng chỉ test trong `pnc-pki-create` cho luồng Plug & Charge ISO 15118-2 của project.

Các certificate này chỉ dùng cho development/regression test. Không dùng private key sinh ra ở đây cho xe thật, EVSE thật hoặc backend thật.

## 1. Prerequisites

Tren Windows, cần có:

- Bash, ví dụ MSYS2/Git Bash.
- OpenSSL 3.x hoặc OpenSSL 1.1.1.
- `xxd` nếu có. Nếu không có `xxd`, script `4_gen_der.sh` sẽ tự dùng fallback `perl`.
- `perl`, thường có sẵn trong MSYS2/Git Bash.

Kiểm tra nhanh:

```powershell
bash --version
openssl version
bash -lc "command -v perl"
```

## 2. Generate certificates

Chạy từ root của repo:

```powershell
bash -lc "cd /c/Users/ADMIN/Desktop/Plug_and_Charge/pnc-pki-create && ./1_v2g.sh; ./2_evse.sh; ./3_evcc.sh; ./4_gen_der.sh"
```

Hoặc nếu đang đứng trong `pnc-pki-create` bằng Bash:

```bash
./1_v2g.sh
./2_evse.sh
./3_evcc.sh
./4_gen_der.sh
```

Thứ tự script:

1. `1_v2g.sh`: tạo V2G Root CA.
2. `2_evse.sh`: tạo CPO Sub-CA1, CPO Sub-CA2, EVSE leaf certificate/key.
3. `3_evcc.sh`: tạo OEM Root, OEM Sub-CA1, OEM Sub-CA2, OEM Provisioning leaf certificate/key và verify chain với V2G Root.
4. `4_gen_der.sh`: convert PEM/key sang DER và tạo `der/evcc_certs.c`.

Khi chạy thành công, `3_evcc.sh` in:

```text
== OpenSSL verify ==
oem/oem_leaf.crt: OK
```

## 3. Generated files

Trust anchor:

- `pnc-pki-create/root/v2g_root.crt`
- `pnc-pki-create/der/v2g_root.der`

EVSE/CPO side:

- `pnc-pki-create/evse/evse_leaf.crt`
- `pnc-pki-create/evse/evse_leaf.key`
- `pnc-pki-create/evse/cpo_sub_ca1.crt`
- `pnc-pki-create/evse/cpo_sub_ca2.crt`
- `pnc-pki-create/evse/evse_chain.pem`
- DER tương ứng trong `pnc-pki-create/der/`.

EVCC/OEM side:

- `pnc-pki-create/oem/oem_leaf.crt`: OEM Provisioning certificate dùng cho `CertificateInstallationReq`.
- `pnc-pki-create/oem/oem_leaf.key`: private key của OEM Provisioning certificate.
- `pnc-pki-create/oem/oem_sub_ca1.crt`
- `pnc-pki-create/oem/oem_sub_ca2.crt`
- `pnc-pki-create/oem/oem_root.crt`
- `pnc-pki-create/oem/oem_leaf_chain.pem`
- DER tương ứng trong `pnc-pki-create/der/`.
- `pnc-pki-create/der/evcc_certs.c`: C arrays kiểu `xxd -i` cho RAM/unit test hoặc firmware bring-up.

## 4. Mapping vao PnC_Helper

Với software crypto, `PnC_Helper` dùng NetX Secure/NetX Crypto API để parse X.509, kiểm tra hạn cert, SHA-256, AES-CBC và ECDH. Khi nạp cert test từ `pnc-pki-create/der`, map như sau:

```c
PnCHlp_CertStoreInit(&gPnCHelper);

PnCHlp_AddV2GRootCert(&gPnCHelper,
                      0,
                      v2g_root_der,
                      v2g_root_der_len,
                      v2g_root_raw_buffer,
                      sizeof(v2g_root_raw_buffer));

PnCHlp_LoadOemProvisioningCert(&gPnCHelper,
                               oem_leaf_der,
                               oem_leaf_der_len,
                               oem_leaf_raw_buffer,
                               sizeof(oem_leaf_raw_buffer),
                               oem_leaf_key_der,
                               oem_leaf_key_der_len,
                               NX_SECURE_X509_KEY_TYPE_EC_DER);
```

Khi backend/EVSE trả contract certificate sau `CertificateInstallationRes` hoặc `CertificateUpdateRes`, dùng:

```c
PnCHlp_LoadContractCert(&gPnCHelper,
                        0,
                        contract_leaf_der,
                        contract_leaf_der_len,
                        contract_raw_buffer,
                        sizeof(contract_raw_buffer),
                        contract_private_key_der,
                        contract_private_key_der_len,
                        NX_SECURE_X509_KEY_TYPE_EC_DER);
```

Trong luồng ISO 15118-2:

- Chưa có contract cert hoặc contract cert đã hết hạn: EVCC gửi `CertificateInstallationReq`.
- Contract cert còn hợp lệ nhưng sắp hết hạn theo policy của EV: EVCC gửi `CertificateUpdateReq`.
- Contract cert còn hợp lệ và chưa tới ngưỡng update: EVCC đi tiếp `PaymentDetailsReq`.

## 5. HSE/NVM note

Nếu bật hardware crypto HSE bằng `PNC_USE_HSE_CRYPTO`, private key không nên nằm dạng plain array trong flash/RAM lâu dài.

Nên lưu trong HSE hoặc key storage bảo mật:

- OEM Provisioning private key.
- Contract certificate private key.
- ECDH ephemeral/private key.
- Derived AES key dùng giải mã encrypted private key trong response.
- Key/signing material dùng XMLDSig/ECDSA.

Nên lưu trong NVM:

- V2G Root CA DER.
- OEM provisioning certificate chain DER.
- Contract certificate chain DER.
- EMAID, PCID.
- Validity metadata: `notBefore`, `notAfter`, trạng thái sắp hết hạn, lần update/install gần nhất.
- Retry/audit state cho CertificateInstallation/CertificateUpdate.

## 6. Cert lifecycle trong Plug & Charge

Trong ISO 15118-2 Plug & Charge, xe không dùng cùng một certificate cho mọi việc. Luồng đúng là: OEM provisioning credential dùng để xin contract credential ban đầu, sau đó contract credential mới được dùng để xác thực sạc với EVSE/backend.

### 6.1. Khi xe xuất xưởng

OEM nạp sẵn cho EVCC:

- OEM Provisioning Certificate.
- OEM Provisioning Private Key.
- OEM Sub-CA chain.
- V2G Root CA hoặc danh sách root CA tin cậy.
- PCID hoặc định danh provisioning của xe.

OEM Provisioning Certificate không phải certificate thanh toán hằng ngày. Nó chứng minh xe là thiết bị hợp lệ do OEM phát hành để xe có thể xin contract certificate qua `CertificateInstallationReq`.

### 6.2. CertificateInstallation

Khi xe cắm vào EVSE và chọn `PaymentOption = Contract`, nếu xe chưa có contract certificate hợp lệ hoặc contract certificate đã hết hạn, EVCC gửi `CertificateInstallationReq`.

Request cần có:

- `OEMProvisioningCert`.
- `ListOfRootCertificateIDs` mà EV tin cậy.
- `DHpublickey` để sinh shared secret.
- XMLDSig/ECDSA signature của request bằng OEM provisioning private key.

EVSE chuyển request về backend/CSMS. Backend/PKI xác minh OEM provisioning chain, sau đó trả `CertificateInstallationRes` gồm:

- `ContractSignatureCertChain`: contract certificate và MO Sub-CA chain.
- `ContractSignatureEncryptedPrivateKey`: private key contract được mã hóa.
- `DHpublickey` phía SECC/backend.
- `EMAID`.
- `ResponseCode`.
- Signature của response.

EVCC xử lý response theo thứ tự:

1. Kiểm tra `ResponseCode`.
2. Verify signature và chain của response với V2G Root CA tin cậy.
3. Tính shared secret bằng ECDH.
4. Derive AES key.
5. Giải mã encrypted contract private key.
6. Kiểm tra contract certificate chưa hết hạn.
7. Lưu contract cert chain, contract private key và EMAID vào storage.

### 6.3. Contract certificate dùng khi sạc

Contract certificate liên kết EV với eMSP thông qua EMAID. Khi xe đã có contract certificate còn hạn:

1. EV verify EVSE certificate trong TLS/session security.
2. EV chọn `PaymentOption = Contract`.
3. EV gửi `PaymentDetailsReq` với EMAID và contract certificate chain.
4. EVSE/backend kiểm tra contract chain, hạn cert, trạng thái revoke, EMAID và quyền authorize.
5. Nếu hợp lệ, EVSE trả `PaymentDetailsRes`, sau đó EV tiếp tục `AuthorizationReq`.

EV phải có contract private key tương ứng với contract certificate. Nếu chỉ có certificate mà mất private key thì không thể chứng minh quyền sở hữu credential PnC.

### 6.4. CertificateUpdate

Nếu contract certificate vẫn còn hợp lệ nhưng sắp hết hạn theo policy của EV/OEM/eMSP, EVCC gửi `CertificateUpdateReq`.

Điều kiện gọi update:

- Đã có contract certificate.
- Có contract private key và EMAID.
- Contract certificate chưa hết hạn.
- Contract certificate nằm trong ngưỡng sắp hết hạn, ví dụ còn dưới 30 ngày hoặc theo policy cấu hình.
- EVSE quảng bá hỗ trợ `CertificateUpdate`.

Nếu contract certificate đã hết hạn, không nên dùng `CertificateUpdateReq`; EVCC phải quay lại `CertificateInstallationReq`.

### 6.5. Quyết định luồng trong code

```text
Không có contract cert/private key/EMAID
=> CertificateInstallationReq

Có contract cert nhưng đã hết hạn
=> CertificateInstallationReq

Có contract cert còn hạn nhưng sắp hết hạn
=> CertificateUpdateReq

Có contract cert còn hạn và chưa cần update
=> PaymentDetailsReq / AuthorizationReq
```

Tóm tắt: OEM certificate là credential ban đầu để xin contract certificate. Contract certificate là credential PnC dùng cho xác thực sạc. EVSE certificate là credential để xe xác thực trụ sạc.

## 7. Regression tests

Sau khi sinh cert, chạy lại regression hiện có:

```powershell
.\tests\run_pnc_ram_regression.cmd
.\tests\run_pnc_flow_tests.cmd
```

Report HTML:

- `tests/PnC_Ram_Regression_Report.html`
- `tests/PnC_Flow_Report.html`

## 8. Troubleshooting

Nếu `4_gen_der.sh` báo `xxd: command not found`, script vẫn tự fallback sang `perl`. Nếu cả `xxd` và `perl` đều không có, cài MSYS2 package tương ứng hoặc chạy trên Git Bash/MSYS2 có Perl.

Nếu verify OEM leaf fail, kiểm tra chain theo thứ tự:

```bash
cat oem/oem_root.crt oem/oem_sub_ca1.crt oem/oem_sub_ca2.crt > /tmp/oem_untrusted_chain.pem
openssl verify -CAfile root/v2g_root.crt -untrusted /tmp/oem_untrusted_chain.pem oem/oem_leaf.crt
```
