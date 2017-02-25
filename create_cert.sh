CERT_NAME=$1_cert.pem
KEY_NAME=$1_key.pem

openssl req -new -x509 -days 365 -nodes -out ${CERT_NAME} -keyout ${KEY_NAME}
