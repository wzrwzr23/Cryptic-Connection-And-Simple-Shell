import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    # try:
    print("Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")
        with open("auth/_certificate_request.csr", mode="rb") as auth:
            authentication = auth.read()
            s.sendall(convert_int_to_bytes(3))
            s.sendall(convert_int_to_bytes(len(authentication)))
            s.sendall(authentication)
        s.listen()
        f = open("auth/server_signed.crt", "rb")
        server_cert_raw = f.read()


        f = open("auth/cacsertificate.crt", "rb")
        ca_cert_raw = f.read()
        ca_cert = x509.load_pem_x509_certificate(
            data=ca_cert_raw, backend=default_backend()
        )
        ca_public_key = ca_cert.public_key()
        server_cert = x509.load_pem_x509_certificate(
            data=server_cert_raw, backend=default_backend()
        )

        ca_public_key.verify(
            signature=server_cert.signature, 
            data=server_cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(), 
            algorithm=server_cert.signature_hash_algorithm,
        )

        server_public_key = server_cert.public_key()

        '''if not ():
                    # Close the connection
            s.sendall(convert_int_to_bytes(2))
            print("Closing connection...")'''


        while (server_cert.not_valid_before <= datetime.utcnow() <= server_cert.not_valid_after):
            filename = input(
                "Enter a filename to send (enter -1 to exit):"
            ).strip()

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:").strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0))
            #M1
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            #M2
            s.sendall(filename_bytes)

            # Send the file
            with open(filename, mode="rb") as fp:
                data = fp.read()
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(data)))
                s.sendall(data)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
