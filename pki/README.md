# **PKI Format Conversion**

Script to convert certificates from **Trialog's** ComboCS EV Simulator (related to the ISO 15118 standards) into the format used by **Ecog-Io's** open-source EVSE Python controller.  

## **Original certificates**
Ensure that the original certificates from Trialog are placed in the following organized folder structure before running the script (they should have been provided in this form by default):

```
original/
├── certs/
├── csrs/
├── privateKeys/
└── passphrase.txt
```

### Folder Components Description:
- **certs/**: Contains the issued certificates.
- **csrs/**: Contains the Certificate Signing Requests (CSRs).
- **privateKeys/**: Holds the private keys associated with the certificates.
- **passphrase.txt**: A plaintext file containing the passphrase used to encrypt and unlock all private keys in the `privateKeys/` folder.

Make sure all files are correctly placed inside the `original/` directory

## **Running**

Run the following command to make the script executable:

```
chmod +x conversion.sh
```

Then execute the script with the desired ISO version:

```
./conversion.sh -v 2
```
or (TODO -20 version)
```
./conversion.sh -v 20
```

## **Converted certificates**
The converted certificates will be stored inside the `converted/` folder, under either `iso15118_2/` or `iso15118_20/`, depending on the version used.
Each folder will maintain a similar structure to the original:

```
converted/
├── iso15118_2/ (or iso15118_20/)
    ├── certs/
    ├── csrs/
    ├── privateKeys/
```

### Key Difference
Unlike the original structure, passphrases for private keys are written in separate `.txt` files, each corresponding to a specific private key. However, all passphrases should still be the same.

# **NOTE**

In a real scenario not all certificates would be stored in the EVSE, but confirmed using OCPP communication. See later