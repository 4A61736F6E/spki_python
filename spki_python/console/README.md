



python -m spki_python.console.spki_python \
--private-key '../spki_openssl/notebook/data/poc/*_private-key.der' \
--signing-request '../spki_openssl/notebook/data/poc/ec_signing-request_*.der' \
--signing-request '../spki_openssl/notebook/data/poc/rsa_signing-request_*.der' \
--signed-public-key '../spki_openssl/notebook/data/poc/ec_self-signed-public-key_*.der' \
--signed-public-key '../spki_openssl/notebook/data/poc/rsa_self-signed-public-key_*.der' \
--digest-algorithm sha256,sha1,md5