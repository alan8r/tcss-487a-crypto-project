# Cryptography class project
This project contains a Java terminal application for asymmetric encryption and digital signatures at the 256-but security level.

This is achieved via implementation of the SHA-3 derived KMACXOF256 primitive (and supporting functions _bytepad_, _encode_string_, _left_encode_, _right_encode_, and the _Keccak_ core algorithm itself) as specified in NIST Special Publication 800-185 (https://dx.doi.org/10.6028/NIST.SP.800-185)

The application contains the following capabilities:
  - Compute a plain cryptographic hash of a file or console input
  - Compute a MAC of a file or console input under a supplied passphrase
  - Encrypt/Decrypt a file symmetrically under a supplied passphrase
  - Elliptic key pair generation via a supplied passphrase
  - Encrypt/Decrypt a file or console input under a supplied elliptic public key file
  - Elliptic file decryption via supplied password
  - Sign a file or console input via supplied password

Compiles via:
```
javac Main.java
```

Runs via:
```
java Main
```

(Tested on Windows 10/11 and Ubuntu 22.04.3 LTS via WSL)
