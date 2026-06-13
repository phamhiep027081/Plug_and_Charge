openssl s_server \
  -accept 51327   \
  -cert evse/evse.crt   \
  -cert_chain evse/cpo.crt   \
  -key  evse/evse.key   \
  -CAfile root/v2g_root.crt   \
  -verify 1 \
  -tls1_2 \
  -state \
  -msg

openssl s_client \
  -connect 127.0.0.1:51327 \
  -cert oem/oem_leaf.crt \
  -key  oem/oem_leaf.key \
  -cert_chain oem/oem.crt \
  -CAfile root/v2g_root.crt \
  -tls1_2 \
  -state \
  -msg \
  -showcerts

