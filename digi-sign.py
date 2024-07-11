import argparse
import sys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.Signature import PKCS1_v1_5

# Hash the data using the specified algorithm
def hash_data(data, algorithm='SHA256'):
    """Hash the data using the specified algorithm."""
    if algorithm == 'SHA256':
        return SHA256.new(data)
    elif algorithm == 'SHA384':
        return SHA384.new(data)
    elif algorithm == 'SHA512':
        return SHA512.new(data)
    else:
        raise ValueError("Unsupported hash algorithm")

# Generate RSA keys
def generate_rsa_keys():
    """Generate RSA private and public keys and save them to files."""
    key = RSA.generate(2048)  # Generate a 2048-bit RSA key
    private_key = key.export_key()  # Export the private key in PEM format
    public_key = key.publickey().export_key()  # Export the public key in PEM format

    with open('private_key.pem', 'wb') as f:
        f.write(private_key)

    with open('public_key.pem', 'wb') as f:
        f.write(public_key)

    print("Keys generated and saved as 'private_key.pem' and 'public_key.pem'")

# Generate a digital signature
def generate_signature(private_key_path, data_path, signature_file, algorithm):
    """Generate a digital signature."""
    print("Generating Signature")
    try:
        # Read private key
        with open(private_key_path, 'rb') as f:
            key = RSA.import_key(f.read())
    except (IOError, ValueError) as e:
        print(f"Error reading private key file: {e}")
        return
    
    try:
        # Read data
        with open(data_path, 'rb') as f:
            data = f.read()
    except (IOError, ValueError) as e:
        print(f"Error reading data file: {e}")
        return
    
    # Create a hash of the data
    h = hash_data(data, algorithm)
    
    # Create a PKCS1_v1_5 signer object
    signer = PKCS1_v1_5.new(key)
    
    # Sign the hash
    signature = signer.sign(h)
    
    try:
        # Save the signature to the specified file
        with open(signature_file, 'wb') as f:
            f.write(signature)
    except (IOError, ValueError) as e:
        print(f"Error writing signature file: {e}")
        return
    
    print(f"Signature saved to {signature_file}")

# Verify a digital signature
def verify_signature(public_key_path, data_path, signature_file, algorithm):
    """Verify a digital signature."""
    print("Verifying Signature")
    try:
        # Read public key
        with open(public_key_path, 'rb') as f:
            key = RSA.import_key(f.read())
    except (IOError, ValueError) as e:
        print(f"Error reading public key file: {e}")
        return
    
    try:
        # Read data
        with open(data_path, 'rb') as f:
            data = f.read()
    except (IOError, ValueError) as e:
        print(f"Error reading data file: {e}")
        return
    
    try:
        # Read signature
        with open(signature_file, 'rb') as f:
            signature = f.read()
    except (IOError, ValueError) as e:
        print(f"Error reading signature file: {e}")
        return
    
    # Create a hash of the data
    h = hash_data(data, algorithm)
    
    # Create a PKCS1_v1_5 verifier object
    verifier = PKCS1_v1_5.new(key)
    
    # Verify the signature
    try:
        if verifier.verify(h, signature):
            print("Signature is valid.")
        else:
            print("Signature is invalid.")
    except (ValueError, TypeError):
        print("Signature verification failed.")

# Main function to parse arguments and call appropriate functions
def main():
    parser = argparse.ArgumentParser(description="Digital Signature Tool")
    parser.add_argument('-s', '--sign', action='store_true', help="Generate a signature")
    parser.add_argument('-v', '--verify', action='store_true', help="Verify a signature")
    parser.add_argument('-g', '--generate', action='store_true', help="Generate RSA keys")
    parser.add_argument('key', nargs='?', help="Path to the private/public key file")
    parser.add_argument('data', nargs='?', help="Path to the data file")
    parser.add_argument('signature', nargs='?', help="Path to the signature file")
    parser.add_argument('--algorithm', choices=['SHA256', 'SHA384', 'SHA512'], default='SHA256', help="Hash algorithm to use (default: SHA256)")

    args = parser.parse_args()

    if args.sign and args.verify:
        print("Error: Choose either sign (-s) or verify (-v), not both.")
        parser.print_help()
        sys.exit(1)
    
    if args.generate:
        # `generate` should not require other arguments
        if args.key or args.data or args.signature:
            print("Error: The -g (generate) option does not require 'key', 'data', or 'signature' arguments.")
            parser.print_help()
            sys.exit(1)
        generate_rsa_keys()
    elif args.sign:
        if not (args.key and args.data and args.signature):
            print("Error: For signing, you must provide 'key', 'data', and 'signature' arguments.")
            parser.print_help()
            sys.exit(1)
        generate_signature(args.key, args.data, args.signature, args.algorithm)
    elif args.verify:
        if not (args.key and args.data and args.signature):
            print("Error: For verification, you must provide 'key', 'data', and 'signature' arguments.")
            parser.print_help()
            sys.exit(1)
        verify_signature(args.key, args.data, args.signature, args.algorithm)
    else:
        print("Error: You must specify either sign (-s), verify (-v), or generate (-g).")
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
