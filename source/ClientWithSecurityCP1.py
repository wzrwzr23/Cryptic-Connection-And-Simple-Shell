
import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback
from tracemalloc import stop

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


def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)

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
        state = True
        try: 

            message = 'this is a secret message'
            message = bytes(message,encoding="utf8")
            message_len = len(message)
            s.sendall(convert_int_to_bytes(3))
            s.sendall(convert_int_to_bytes(message_len))
            s.sendall(message)

            f = open("auth/cacsertificate.crt", "rb")
            ca_cert_raw = f.read()

            ca_cert = x509.load_pem_x509_certificate(
                data=ca_cert_raw, backend=default_backend()
            )
            ca_public_key = ca_cert.public_key()



            server_cert_len = convert_bytes_to_int(read_bytes(s, 8))
            server_cert_raw = read_bytes(s, server_cert_len)

            server_cert = x509.load_pem_x509_certificate(
                data=server_cert_raw, backend=default_backend()
            )


            ca_public_key.verify(
                signature=server_cert.signature, # signature bytes to  verify
                data=server_cert.tbs_certificate_bytes, # certificate data bytes that was signed by CA
                padding=padding.PKCS1v15(), # padding used by CA bot to sign the the server's csr
                algorithm=server_cert.signature_hash_algorithm,
            )
            server_public_key = server_cert.public_key()
            signed_message_len = convert_bytes_to_int(read_bytes(s, 8))
            signed_message = read_bytes(s, signed_message_len)


            server_public_key.verify(
                signed_message,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

        except:
            state = False


        while state:
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
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            # Send the file
            filename2 = "enc_" + filename.split("/")[-1]
            with open(filename, mode="rb") as fp:
                data = fp.read()
                s.sendall(convert_int_to_bytes(1))
                data_block = 62
                data_length = len(data)
                count = 0
                data_total = bytes(0)
                while data_block*count < data_length:
                    
                    block1 = data_block*count
                    block2 = data_block*(count+1)

                    if data_block*(count+1) < data_length:
                        encrypt = data[block1:block2]
                    else:
                        encrypt = data[block1:]
                    count+=1
                    # print(count)

                    encrypted_message = server_public_key.encrypt(
                        encrypt,
                        padding.OAEP(
                            mgf=padding.MGF1(hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                    data_total += encrypted_message
                    s.sendall(convert_int_to_bytes(len(encrypted_message)))
                    s.sendall(encrypted_message)
                s.sendall(convert_int_to_bytes(18446744073709551615))

            with open(
                f"send_files_enc/{filename2}", mode="wb"
            ) as fp:
                fp.write(data_total)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
