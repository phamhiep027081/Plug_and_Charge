#evse.sh
rm -rf evse
mkdir -p evse
# SECC/CPO SubCA1
openssl ecparam -name prime256v1 -genkey -noout -out evse/cpo_sub_ca1.key
openssl req -new -key evse/cpo_sub_ca1.key -config cnf/cpo_sub_ca1.cnf -out evse/cpo_sub_ca1.csr 

openssl x509 -req -in evse/cpo_sub_ca1.csr -set_serial 2 \
      -CA root/v2g_root.crt -CAkey  root/v2g_root.key -CAcreateserial \
      -days 3650 -extfile cnf/cpo_sub_ca1.cnf -extensions cpo_ca_ext \
      -out evse/cpo_sub_ca1.crt

# SECC/CPO SubCA2
openssl ecparam -name prime256v1 -genkey -noout -out evse/cpo_sub_ca2.key
openssl req -new -key evse/cpo_sub_ca2.key -config cnf/cpo_sub_ca2.cnf -out evse/cpo_sub_ca2.csr 

openssl x509 -req -in evse/cpo_sub_ca2.csr -set_serial 3 \
      -CA evse/cpo_sub_ca1.crt -CAkey  evse/cpo_sub_ca1.key -CAcreateserial \
      -days 3650 -extfile cnf/cpo_sub_ca2.cnf -extensions cpo_ca_ext \
      -out evse/cpo_sub_ca2.crt

# Key SECC (server)
openssl ecparam -name prime256v1 -genkey -noout -out evse/evse_leaf.key
openssl req -new -key evse/evse_leaf.key -config cnf/evse_leaf.cnf -out evse/evse_leaf.csr

openssl x509 -req -in evse/evse_leaf.csr -set_serial 4 \
      -CA evse/cpo_sub_ca2.crt -CAkey evse/cpo_sub_ca2.key -CAcreateserial \
      -days 365 -extfile cnf/evse_leaf.cnf -extensions evse_ext \
      -out evse/evse_leaf.crt
# Chuỗi server (leaf + intermediates + root)
cat  evse/evse_leaf.crt  evse/cpo_sub_ca1.crt evse/cpo_sub_ca2.crt > evse/evse_chain.pem
