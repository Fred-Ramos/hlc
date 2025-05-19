#!/bin/bash

# Default version (ISO 15118-2)
ISO_VERSION="2"

# Parse command-line options
while getopts "v:" opt; do
  case $opt in
    v)
      if [[ "$OPTARG" == "2" || "$OPTARG" == "20" ]]; then
        ISO_VERSION="$OPTARG"
      else
        echo "Invalid version specified. Use -v 2 for ISO 15118-2 or -v 20 for ISO 15118-20."
        exit 1
      fi
      ;;
    *)
      echo "Invalid parameters. For correct usage do: $0 -v [2|20]"
      exit 1
      ;;
  esac
done

# Define source and destination directories based on the version
SOURCE_DIR="original"
DEST_DIR="converted/iso15118_${ISO_VERSION}"

# Initialize empty maps
declare -A KEY_MAP CERT_MAP CSR_MAP

if [[ "$ISO_VERSION" == "2" ]]; then
    echo "Configuring for ISO 15118-2..."

    # **ISO 15118-2 Keys**
    KEY_MAP=(
        ["contractCert.key"]="contractLeaf.key"
        ["moSubCA2.key"]="moSubCA2.key"
        ["moSubCA1.key"]="moSubCA1.key"
        ["moRootCA.key"]="moRootCA.key"
        ["seccCert.key"]="seccLeaf.key"
        ["cpoSubCA2.key"]="cpoSubCA2.key"
        ["cpoSubCA1.key"]="cpoSubCA1.key"
        ["v2gRootCA.key"]="v2gRootCA.key"
    )

    # **ISO 15118-2 Certificates**
    CERT_MAP=(
        ["contractCert.pem"]="contractLeafCert.pem"
        ["moSubCA2.pem"]="moSubCA2Cert.pem"
        ["moSubCA1.pem"]="moSubCA1Cert.pem"
        ["moRootCA.pem"]="moRootCACert.pem"
        ["seccCert.pem"]="seccLeafCert.pem"
        ["cpoSubCA2.pem"]="cpoSubCA2Cert.pem"
        ["cpoSubCA1.pem"]="cpoSubCA1Cert.pem"
        ["v2gRootCA.pem"]="v2gRootCACert.pem"
    )

    # **ISO 15118-2 CSRs**
    CSR_MAP=(
        ["contractCert.csr"]="contractLeafCert.csr"
        ["moSubCA2.csr"]="moSubCA2.csr"
        ["moSubCA1.csr"]="moSubCA1.csr"
        ["moRootCA.csr"]="moRootCA.csr"
        ["seccCert.csr"]="seccLeafCert.csr"
        ["cpoSubCA2.csr"]="cpoSubCA2.csr"
        ["cpoSubCA1.csr"]="cpoSubCA1.csr"
        ["v2gRootCA.csr"]="v2gRootCA.csr"
    )

else
    echo "Configuring for ISO 15118-20..."

    # **ISO 15118-20 Keys**
    KEY_MAP=(
        ["contractCert.key"]="contractLeaf.key"
        ["moSubCA2.key"]="moSubCA2.key"
        ["moSubCA1.key"]="moSubCA1.key"
        ["moRootCA.key"]="moRootCA.key"
        ["secc20Cert.key"]="seccLeaf.key" 
        ["cpo20SubCA2.key"]="cpoSubCA2.key" 
        ["cpo20SubCA1.key"]="cpoSubCA1.key" 
        ["v2g20RootCA.key"]="v2gRootCA.key" 
        ["cpsLeafCert.key"]="cpsLeaf.key"
        ["cpsSubCA2.key"]="cpsSubCA2.key"
        ["cpsSubCA1.key"]="cpsSubCA1.key"
        ["oemProvCert.key"]="oemLeaf.key"
        ["oemSubCA2.key"]="oemSubCA2.key"
        ["oemSubCA1.key"]="oemSubCA1.key"
        ["oemRootCA.key"]="oemRootCA.key"
    )

    # **ISO 15118-20 Certificates**
    CERT_MAP=(
        ["contractCert.pem"]="contractLeafCert.pem"
        ["moSubCA2.pem"]="moSubCA2Cert.pem"
        ["moSubCA1.pem"]="moSubCA1Cert.pem"
        ["moRootCA.pem"]="moRootCACert.pem"
        ["secc20Cert.pem"]="seccLeafCert.pem" 
        ["cpo20SubCA2.pem"]="cpoSubCA2Cert.pem"
        ["cpo20SubCA1.pem"]="cpoSubCA1Cert.pem" 
        ["v2g20RootCA.pem"]="v2gRootCACert.pem" 
        ["cpsLeafCert.pem"]="cpsLeafCert.pem"
        ["cpsSubCA2.pem"]="cpsSubCA2Cert.pem"
        ["cpsSubCA1.pem"]="cpsSubCA1Cert.pem"
        ["oemProvCert.pem"]="oemLeafCert.pem"
        ["oemSubCA2.pem"]="oemSubCA2Cert.pem"
        ["oemSubCA1.pem"]="oemSubCA1Cert.pem"
        ["oemRootCA.pem"]="oemRootCACert.pem"
    )

    # **ISO 15118-20 CSRs**
    CSR_MAP=(
        ["contractCert.csr"]="contractLeafCert.csr"
        ["moSubCA2.csr"]="moSubCA2.csr"
        ["moSubCA1.csr"]="moSubCA1.csr"
        ["moRootCA.csr"]="moRootCA.csr"
        ["seccCert.csr"]="seccLeafCert.csr"
        ["cpoSubCA2.csr"]="cpoSubCA2.csr"
        ["cpoSubCA1.csr"]="cpoSubCA1.csr"
        ["v2gRootCA.csr"]="v2gRootCA.csr"
        ["cpsLeafCert.csr"]="cpsLeafCert.csr"
        ["cpsSubCA2.csr"]="cpsSubCA2.csr"
        ["cpsSubCA1.csr"]="cpsSubCA1.csr"
        ["oemProvCert.csr"]="oemLeafCert.csr"
        ["oemSubCA2.csr"]="oemSubCA2.csr"
        ["oemSubCA1.csr"]="oemSubCA1.csr"
        ["oemRootCA.csr"]="oemRootCA.csr"
    )
fi

# Create necessary directory structure
mkdir -p "$DEST_DIR/certs" "$DEST_DIR/csrs" "$DEST_DIR/private_keys"

echo "Converting Keys into Ecog-Io's ISO 15118-${ISO_VERSION} naming"

for key in "${!KEY_MAP[@]}"; do
    if [[ -f "$SOURCE_DIR/privateKeys/$key" ]]; then
        cp "$SOURCE_DIR/privateKeys/$key" "$DEST_DIR/private_keys/${KEY_MAP[$key]}"
    fi
done

echo "Converting Certificates into Ecog-Io's ISO 15118-${ISO_VERSION} naming"
echo "Certificates converted from .pem to .der using OpenSSL x509..."
for cert in "${!CERT_MAP[@]}"; do
    if [[ -f "$SOURCE_DIR/certs/$cert" ]]; then
        cp "$SOURCE_DIR/certs/$cert" "$DEST_DIR/certs/${CERT_MAP[$cert]}"
        openssl x509 -outform der -in "$SOURCE_DIR/certs/$cert" -out "$DEST_DIR/certs/${CERT_MAP[$cert]%.pem}.der"
    fi
done

echo "Converting Certificate Signing Requests into Ecog-Io's ISO 15118-${ISO_VERSION} naming"
for csr in "${!CSR_MAP[@]}"; do
    if [[ -f "$SOURCE_DIR/csrs/$csr" ]]; then
        cp "$SOURCE_DIR/csrs/$csr" "$DEST_DIR/csrs/${CSR_MAP[$csr]}"
    fi
done

# Generate cpoCertChain.pem
if [[ -f "$DEST_DIR/certs/seccLeafCert.pem" && -f "$DEST_DIR/certs/cpoSubCA2Cert.pem" && -f "$DEST_DIR/certs/cpoSubCA1Cert.pem" ]]; then
    echo "Generating cpoCertChain.pem..."
    cat "$DEST_DIR/certs/seccLeafCert.pem" "$DEST_DIR/certs/cpoSubCA2Cert.pem" "$DEST_DIR/certs/cpoSubCA1Cert.pem" > "$DEST_DIR/certs/cpoCertChain.pem"
fi

# Generate oemCertChain.pem
if [[ -f "$DEST_DIR/certs/oemLeafCert.pem" && -f "$DEST_DIR/certs/oemSubCA2Cert.pem" && -f "$DEST_DIR/certs/oemSubCA1Cert.pem" ]]; then
    echo "Generating oemCertChain.pem..."
    cat "$DEST_DIR/certs/oemLeafCert.pem" "$DEST_DIR/certs/oemSubCA2Cert.pem" "$DEST_DIR/certs/oemSubCA1Cert.pem" > "$DEST_DIR/certs/oemCertChain.pem"
fi

# Generate missing password .txt files using passphrase.txt
echo "Generating missing password files..."
PASSPHRASE_FILE="$SOURCE_DIR/passphrase.txt"
if [ -f "$PASSPHRASE_FILE" ]; then
    PASSPHRASE=$(cat "$PASSPHRASE_FILE")
    
    declare -a PASSWORD_FILES=(
        "contractLeafPassword.txt"
        "cpsLeafPassword.txt"
        "moSubCA2LeafPassword.txt"
        "oemLeafPassword.txt"
        "seccLeafPassword.txt"
    )

    for password_file in "${PASSWORD_FILES[@]}"; do
        echo "$PASSPHRASE" > "$DEST_DIR/private_keys/$password_file"
    done
else
    echo "Error: Passphrase file not found at $PASSPHRASE_FILE!"
    exit 1
fi

# Generate moCertChain.p12
if [[ -f "$DEST_DIR/certs/moSubCA1Cert.pem" && -f "$DEST_DIR/certs/moSubCA2Cert.pem" && -f "$DEST_DIR/certs/moRootCACert.pem" ]]; then
    echo "Generating moCertChain.p12..."
    openssl pkcs12 -export -out "$DEST_DIR/certs/moCertChain.p12" \
        -inkey "$DEST_DIR/private_keys/moSubCA2.key" \
        -passin pass:"$PASSPHRASE" \
        -in "$DEST_DIR/certs/moSubCA2Cert.pem" \
        -certfile "$DEST_DIR/certs/moSubCA1Cert.pem" \
        -certfile "$DEST_DIR/certs/moRootCACert.pem" \
        -passout pass:"$PASSPHRASE"
fi

# Generate cpsCertChain.p12
if [[ -f "$DEST_DIR/certs/cpsLeafCert.pem" && -f "$DEST_DIR/certs/cpsSubCA2Cert.pem" && -f "$DEST_DIR/certs/cpsSubCA1Cert.pem" ]]; then
    echo "Generating cpsCertChain.p12..."
    openssl pkcs12 -export -out "$DEST_DIR/certs/cpsCertChain.p12" \
        -inkey "$DEST_DIR/private_keys/cpsLeaf.key" \
        -passin pass:"$PASSPHRASE" \
        -in "$DEST_DIR/certs/cpsLeafCert.pem" \
        -certfile "$DEST_DIR/certs/cpsSubCA2Cert.pem" \
        -certfile "$DEST_DIR/certs/cpsSubCA1Cert.pem" \
        -passout pass:"$PASSPHRASE"
fi


# Generate intermediateMOCACerts.pem (MO SubCAs in order 2->1)
if [[ -f "$DEST_DIR/certs/moSubCA2Cert.pem" && -f "$DEST_DIR/certs/moSubCA1Cert.pem" ]]; then
    echo "Generating intermediateMOCACerts.pem..."
    cat "$DEST_DIR/certs/moSubCA2Cert.pem" "$DEST_DIR/certs/moSubCA1Cert.pem" > "$DEST_DIR/certs/intermediateMOCACerts.pem"
fi

# Generate intermediateCPSCACerts.pem (CPS SubCAs in order 1->2)
if [[ -f "$DEST_DIR/certs/cpsSubCA1Cert.pem" && -f "$DEST_DIR/certs/cpsSubCA2Cert.pem" ]]; then
    echo "Generating intermediateCPSCACerts.pem..."
    cat "$DEST_DIR/certs/cpsSubCA1Cert.pem" "$DEST_DIR/certs/cpsSubCA2Cert.pem" > "$DEST_DIR/certs/intermediateCPSCACerts.pem"
fi

# Convert specific private keys to PKCS#8 DER format
for key in "moSubCA2" "cpsLeaf" "contractLeaf" "oemLeaf" "seccLeaf"; do
    if [[ -f "$DEST_DIR/private_keys/${key}.key" ]]; then
        echo "Converting ${key}.key to ${key}.pkcs8.der..."
        openssl pkcs8 -topk8 -nocrypt -in "$DEST_DIR/private_keys/${key}.key" -passin pass:"$PASSPHRASE" -outform DER -out "$DEST_DIR/private_keys/${key}.pkcs8.der"
    fi
done

echo "Conversion complete! Files are in '$DEST_DIR'."
