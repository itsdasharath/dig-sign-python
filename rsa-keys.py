from Crypto.PublicKey import RSA

def generate_rsa_keys():
    key = RSA.generate(2048)  # Generate a 2048-bit RSA key
    private_key = key.export_key()  # Export the private key in PEM format
    public_key = key.publickey().export_key()  # Export the public key in PEM format

    with open('private_key.pem', 'wb') as f:
        f.write(private_key)

    with open('public_key.pem', 'wb') as f:
        f.write(public_key)

    print("Keys generated and saved as 'private_key.pem' and 'public_key.pem'")

if __name__ == "__main__":
    generate_rsa_keys()
