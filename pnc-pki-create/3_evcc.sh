# evcc.sh

rm -rf oem
mkdir -p oem
# OEM Root CA
openssl ecparam -name prime256v1 -genkey -noout -out  oem/oem_root.key
openssl req -new -key oem/oem_root.key \
  -config cnf/oem_root.cnf -out oem/oem_root.csr

openssl x509 -req -in oem/oem_root.csr -set_serial 40 \
  -CA root/v2g_root.crt -CAkey root/v2g_root.key -CAcreateserial \
  -days 1825 -extfile cnf/oem_root.cnf -extensions oem_ca_ext \
  -out oem/oem_root.crt

# 1) Tạo OEM Sub-CA1
openssl ecparam -name prime256v1 -genkey -noout -out  oem/oem_sub_ca1.key
openssl req -new -key oem/oem_sub_ca1.key \
  -config cnf/oem_sub_ca1.cnf -out oem/oem_sub_ca1.csr

openssl x509 -req -in oem/oem_sub_ca1.csr -set_serial 41 \
  -CA oem/oem_root.crt -CAkey oem/oem_root.key -CAcreateserial \
  -days 1825 -extfile cnf/oem_sub_ca1.cnf -extensions oem_ca_ext \
  -out oem/oem_sub_ca1.crt

# 1) Tạo OEM Sub-CA1
openssl ecparam -name prime256v1 -genkey -noout -out  oem/oem_sub_ca2.key
openssl req -new -key oem/oem_sub_ca2.key \
  -config cnf/oem_sub_ca2.cnf -out oem/oem_sub_ca2.csr

openssl x509 -req -in oem/oem_sub_ca2.csr -set_serial 42 \
  -CA oem/oem_sub_ca1.crt -CAkey oem/oem_sub_ca1.key -CAcreateserial \
  -days 1825 -extfile cnf/oem_sub_ca2.cnf -extensions oem_ca_ext \
  -out oem/oem_sub_ca2.crt

# 2) Tạo OEM Provisioning leaf
openssl ecparam -name prime256v1 -genkey -noout -out oem/oem_leaf.key

openssl req -new -key oem/oem_leaf.key \
  -config cnf/oem_leaf.cnf -out oem/oem_leaf.csr

openssl x509 -req -in oem/oem_leaf.csr -set_serial 43 \
  -CA oem/oem_sub_ca2.crt -CAkey oem/oem_sub_ca2.key -CAcreateserial \
  -days 730 -extfile cnf/oem_leaf.cnf -extensions oem_leaf_ext \
  -out oem/oem_leaf.crt

# 3) Chuỗi (leaf + OEM Sub-CA) — Root do EV/đối tác giữ sẵn
cat oem/oem_leaf.crt oem/oem_root.crt oem/oem_sub_ca2.crt  oem/oem_sub_ca2.crt  > oem/oem_leaf_chain.pem


# 4) Kiểm tra nhanh
echo "== OpenSSL verify =="
openssl verify -CAfile root/v2g_root.crt \
  -untrusted oem/oem_root.crt oem/oem_leaf.crt