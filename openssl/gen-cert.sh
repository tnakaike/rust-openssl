#!/bin/bash

HOST=${1:-localhost}
CERT_LIFE_TIME_MINS=${2:-1}
SIZE=2048
OUTDIR=cert

rm -rf ${OUTDIR}
mkdir -p ${OUTDIR}

function initializeDemoCA() {
    rm -rf demoCA
    mkdir demoCA
    mkdir -p demoCA/certs
    mkdir -p demoCA/private
    mkdir -p demoCA/crl
    mkdir -p demoCA/newcerts
    chmod 700 demoCA/private
    echo "01" > demoCA/serial
    touch demoCA/index.txt
    return 0
}

OS=`uname`
if [ ${OS} = Darwin ]; then
    ENDDATE=`date -u -v+${CERT_LIFE_TIME_MINS}M "+%Y%m%d%H%M%S"`
    OPENSSLCONF=/usr/local/etc/openssl@1.1/openssl.cnf
    echo ${ENDDATE}
elif [ ${OS} = Linux ]; then
    ENDDATE=`date -u --date "${CERT_LINE_TIME_MINS} mins" "+%Y%m%d%H%M%S"`
    OPENSSLCONF=/etc/ssl/openssl.cnf
fi

# Self-signed CA certificate
openssl genrsa -out ${OUTDIR}/ca-key.pem ${SIZE}
openssl req -new -x509 -key ${OUTDIR}/ca-key.pem -out ${OUTDIR}/root-ca.pem -subj "/CN=CA"

# Server certificate
initializeDemoCA
openssl genrsa -out ${OUTDIR}/server-key.pem ${SIZE}
openssl req -new -key ${OUTDIR}/server-key.pem -out ${OUTDIR}/server.csr -subj "/CN=${HOST}" -addext "subjectAltName = DNS:${HOST}"
# openssl x509 -req -in ${OUTDIR}/server.csr -CA ${OUTDIR}/root-ca.pem -CAkey ${OUTDIR}/ca-key.pem -CAcreateserial -out ${OUTDIR}/server-cert.pem -extfile <(printf "subjectAltName=DNS:${HOST}")
openssl ca -batch -extfile <(printf "subjectAltName=DNS:${HOST}") -config ${OPENSSLCONF} -policy policy_anything -out ${OUTDIR}/server-cert.pem -enddate ${ENDDATE}Z -cert ${OUTDIR}/root-ca.pem -keyfile ${OUTDIR}/ca-key.pem -infiles ${OUTDIR}/server.csr

# Client certificate
initializeDemoCA
openssl genrsa -out ${OUTDIR}/client-key.pem ${SIZE}
openssl req -new -key ${OUTDIR}/client-key.pem -out ${OUTDIR}/client.csr -subj "/CN=${HOST}" -addext "subjectAltName = DNS:${HOST}"
# openssl x509 -req -in ${OUTDIR}/client.csr -CA ${OUTDIR}/root-ca.pem -CAkey ${OUTDIR}/ca-key.pem -CAcreateserial -out ${OUTDIR}/client-cert.pem -extfile <(printf "subjectAltName=DNS:${HOST}")
openssl ca -batch  -extfile <(printf "subjectAltName=DNS:${HOST}") -config ${OPENSSLCONF} -policy policy_anything -out ${OUTDIR}/client-cert.pem -enddate ${ENDDATE}Z -cert ${OUTDIR}/root-ca.pem -keyfile ${OUTDIR}/ca-key.pem -infiles ${OUTDIR}/client.csr
openssl pkcs8 -nocrypt -topk8 -inform PEM -outform PEM -in ${OUTDIR}/client-key.pem -out ${OUTDIR}/client-pkcs8-key.pem

