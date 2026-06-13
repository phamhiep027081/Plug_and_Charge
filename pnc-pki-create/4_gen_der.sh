
#der.sh
rm -rf der
mkdir -p der
# V2GRoot DER
openssl x509 -in root/v2g_root.crt -outform DER -out der/v2g_root.der

#EVSE 
openssl x509 -in evse/evse_leaf.crt         -outform DER -out der/evse_leaf.der
openssl x509 -in evse/cpo_sub_ca1.crt       -outform DER -out der/cpo_sub_ca1.der
openssl x509 -in evse/cpo_sub_ca2.crt       -outform DER -out der/cpo_sub_ca2.der
openssl ec   -in evse/evse_leaf.key         -outform DER -out der/evse_leaf_key.der

# EVCC 
openssl x509 -in oem/oem_root.crt           -outform DER -out der/oem_root.der
openssl x509 -in oem/oem_sub_ca1.crt        -outform DER -out der/oem_sub_ca1.der
openssl x509 -in oem/oem_sub_ca2.crt        -outform DER -out der/oem_sub_ca2.der
openssl x509 -in oem/oem_leaf.crt           -outform DER -out der/oem_leaf.der
openssl ec   -in oem/oem_leaf.key           -outform DER -out der/oem_leaf_key.der


cd der
# EVSE
# xxd -i evse_leaf.der        >  evse_certs.c
# xxd -i evse_leaf_key.der    >> evse_certs.c
# xxd -i cpo_sub_ca1.der      >> evse_certs.c
# xxd -i cpo_sub_ca2.der      >> evse_certs.c

#  EVCC
xxd -i oem_root.der         >  evcc_certs.c
xxd -i oem_leaf.der         >> evcc_certs.c
xxd -i oem_leaf_key.der     >> evcc_certs.c
xxd -i oem_sub_ca1.der      >> evcc_certs.c
xxd -i oem_sub_ca2.der      >> evcc_certs.c
xxd -i v2g_root.der         >> evcc_certs.c
