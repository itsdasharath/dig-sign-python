# Digital Signature Verification Project

This project aims to implement a digital signature verification system. It allows users to verify the authenticity and integrity of digitally signed documents.

## Features

- Verify digital signatures using public key cryptography.
- Support for multiple signature algorithms (e.g., RSA, DSA, ECDSA).
- Intuitive command-line interface for easy usage.
- Detailed error handling and informative error messages.
- Extensible architecture for adding new signature algorithms.

## Installation

1. Clone the repository:

    ```shell
    git clone https://github.com/itsdasharath/dig-sign-python.git
    ```

2. Install the required dependencies:
    ```shell
        pip install pycryptodome  
    ```

## Usage

1. Generate a key pair (public and private key).
    
    ```shell
     python rsa-keys.py
    ```

2. Sign a document using the private key:

    ```shell
    python digi-sig.py -s path/to/private_key.pem path/to/data_file.txt path/to/signature.sig 
    ```

3. Verify the signature using the public key:

    ```shell
    
    python digi-sig.py -v path/to/public_key.pem path/to/data_file.txt path/to/signature.sig 
    ```

 -s for generating a signature.
 -v for verifying a signature.
    
optional
 --algorithm for specifying the hash algorithm (SHA256, SHA384, SHA512).

## Contributing

Contributions are welcome! If you have any ideas, suggestions, or bug reports, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).