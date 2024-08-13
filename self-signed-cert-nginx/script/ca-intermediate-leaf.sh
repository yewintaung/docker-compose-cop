
#############################################################
################## 1. Generate the Root CA ##################
#############################################################

ROOT_CN='Root CA'
INTERMEDIATE_CN='Intermediate CA'
LEAF_CN=apiserver.yewint.com
LEAF_CN_web=webserver.yewint.com

# Step 1.1: Create the Root CA's Private Key
openssl genrsa -out root_private_key.key 4096

# step 1.2: Create a Configuration File for the Root Certificate
cat <<EOF > root_cert.ext
[ req ]
default_bits       = 4096
default_md         = sha256
prompt             = no
distinguished_name = dn
x509_extensions    = v3_ca

[ dn ]
#C  = MM
#ST = Mandalay
#L  = May Myo
#O  = Ye Wint Corp
OU = Group IT
CN = ${ROOT_CN}

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:TRUE, pathlen:1
keyUsage = critical, keyCertSign, cRLSign
EOF

# Step 1.3: Create the Root CA's Self-Signed Certificate
openssl req -x509 -sha256 -nodes -extensions v3_ca -key root_private_key.key -days 3650 -out root_certificate.crt -config root_cert.ext


#####################################################################
################## 2. Generate the Intermediate CA ##################
#####################################################################
# Step 2.1: Create the Intermediate CA's Private Key
openssl genrsa -out intermediate_private_key.key 4096

# Step 2.2: Create a Configuration File for the Root Certificate
# intermediate_cert.cnf
cat <<EOF > intermediate_cert.ext
[ req ]
default_bits       = 4096
default_md         = sha256
prompt             = no
distinguished_name = dn
req_extensions     = v3_ca

[ dn ]
#C  = MM
#ST = Mandalay
#L  = May Myo
#O  = Ye Wint Corp
OU = Group IT
CN = ${INTERMEDIATE_CN}

[ v3_ca ]
keyUsage = critical, keyCertSign, cRLSign
basicConstraints = CA:TRUE, pathlen:0
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = intermediate.example.com
EOF

# Step 2.3: Create a CSR for the Intermediate CA
openssl req -new -sha256 -nodes -key intermediate_private_key.key -out intermediate_csr.pem -config intermediate_cert.ext

# Step 2.4: Create a Configuration File for the Intermediate Certificate (Optional)
# This configuration file will specify that the intermediate certificate is allowed to sign other certificates.
# intermediate_cert_ext.cnf:
cat <<EOF > intermediate_cert_extension.ext
[ v3_ca ]
keyUsage = keyCertSign, cRLSign
basicConstraints = CA:TRUE, pathlen:0
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = intermediate.example.com
EOF

# Step 2.5: Sign the Intermediate CA's Certificate with the Root CA
openssl x509 -req -extensions v3_ca -in intermediate_csr.pem -CA root_certificate.crt -CAkey root_private_key.key -CAcreateserial -out intermediate_certificate.crt -days 1825 -sha256 -extfile intermediate_cert_extension.ext

###################################################################################
################## 3. Generate the Leaf (End-Entity) Certificate ##################
###################################################################################

# Step 3.1: Create the Leaf Private Key
openssl genrsa -out leaf_private_key.key 4096

# Step 3.2: Create a Configuration File for the Leaf Certificate
# leaf_cert.cnf
cat <<EOF > leaf_cert.ext
[ req ]
default_bits       = 4096
default_md         = sha256
prompt             = no
distinguished_name = dn
req_extensions     = v3_ca

[ dn ]
#C  = MM
#ST = Mandalay
#L  = May Myo
#O  = Ye Wint Corp
#OU = Group IT
CN = www.${LEAF_CN}

[ v3_ca ]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
basicConstraints = CA:FALSE
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${LEAF_CN}
DNS.2 = www.${LEAF_CN}
EOF

# Step 3.3: Create a CSR for the Leaf CA
openssl req -new -sha256 -nodes -key leaf_private_key.key -out leaf_csr.pem -config leaf_cert.ext

# Step 3.4: Create a Configuration File for the Leaf Certificate (Optional)
# leaf_cert_ext.cnf:
cat <<EOF > leaf_cert_extension.ext
[ v3_ca ]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
basicConstraints = CA:FALSE
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${LEAF_CN}
DNS.2 = www.${LEAF_CN}
EOF
openssl x509 -req -extensions v3_ca -in leaf_csr.pem -CA intermediate_certificate.crt -CAkey intermediate_private_key.key -CAcreateserial -out leaf_certificate.crt -days 365 -sha256 -extfile leaf_cert_extension.ext



###################################################################################
################## 4. Generate the Leaf (End-Entity) Certificate ##################
###################################################################################


# Step 4.1: Create a Configuration File for the Leaf Certificate
# leaf_cert_web_server.cnf
cat <<EOF > leaf_cert_web_server.ext
[ req ]
default_bits       = 4096
default_md         = sha256
prompt             = no
distinguished_name = dn
req_extensions     = v3_ca

[ dn ]
#C  = MM
#ST = Mandalay
#L  = May Myo
#O  = Ye Wint Corp
#OU = Group IT
CN = www.${LEAF_CN_web}

[ v3_ca ]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
basicConstraints = CA:FALSE
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${LEAF_CN_web}
DNS.2 = www.${LEAF_CN_web}
EOF

# Step 3.3: Create a CSR for the Leaf CA
openssl req -new -sha256 -nodes -key leaf_private_key.key -out leaf_web_csr.pem -config leaf_cert_web_server.ext

# Step 3.4: Create a Configuration File for the Leaf Certificate (Optional)
# leaf_cert_ext.cnf:
cat <<EOF > leaf_cert_web_server_extension.ext
[ v3_ca ]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
basicConstraints = CA:FALSE
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${LEAF_CN_web}
DNS.2 = www.${LEAF_CN_web}
EOF
openssl x509 -req -extensions v3_ca -in leaf_web_csr.pem -CA intermediate_certificate.crt -CAkey intermediate_private_key.key -CAcreateserial -out leaf_web_certificate.crt -days 365 -sha256 -extfile leaf_cert_web_server_extension.ext


######## verify with CA ######
echo -e "\n Verifying intermediate cert with root cert >>> "
openssl verify -CAfile root_certificate.crt intermediate_certificate.crt

echo -e "\n Verifying leaf api server cert with root and intermediate cert >>> "
cat root_certificate.crt intermediate_certificate.crt > combined_certificates.crt
openssl verify -CAfile combined_certificates.crt leaf_certificate.crt

echo -e "\n Verifying leaf web server cert with root and intermediate cert >>> "
openssl verify -CAfile combined_certificates.crt leaf_web_certificate.crt

# Optionally, clean up the temporary combined file
rm combined_certificates.crt