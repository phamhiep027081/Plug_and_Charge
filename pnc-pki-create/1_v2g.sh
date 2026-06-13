#v2g.sh
rm -r root
mkdir -p root
openssl ecparam -name prime256v1 -genkey -noout -out root/v2g_root.key
openssl req -new -x509 -key root/v2g_root.key -days 3650 -config cnf/v2g_root.cnf -out root/v2g_root.crt  -set_serial 1