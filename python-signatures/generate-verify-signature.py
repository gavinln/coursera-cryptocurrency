import logging
import pathlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

SCRIPT_DIR = pathlib.Path(__file__).parent.resolve()


def get_dsa_private_key():
    return dsa.generate_private_key(
        key_size=1024,
        backend=default_backend()
    )


def sign_dsa_data(private_key, data):
    return private_key.sign(
        data,
        hashes.SHA1()
    )


def write_public_key_openssh(key_path, public_key):
    with key_path.open(mode='wb') as f:
        f.write(public_key.public_bytes(
                serialization.Encoding.OpenSSH,
                serialization.PublicFormat.OpenSSH))


def read_public_key_openssh(key_path):
    with key_path.open(mode="rb") as key_file:
        public_key = serialization.load_ssh_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key


def read_binary(file_path):
    with file_path.open(mode='rb') as f:
        data = f.read()
        logger.debug('read {} bytes from file {}'.format(
            len(data), file_path.resolve()))
        return data


def write_binary(file_path, data):
    with file_path.open(mode='wb') as f:
        f.write(data)
        logger.debug('wrote {} bytes to file {}'.format(
            len(data), file_path.resolve()))


def generate_key_signature(data):
    private_key = get_dsa_private_key()
    public_key = private_key.public_key()
    signature = sign_dsa_data(private_key, data)
    return (public_key, signature)


def main():
    logger.debug('in main')
    JAVA_SIG_DIR = SCRIPT_DIR / '..' / 'java-signatures'
    data_file = JAVA_SIG_DIR / 'data.txt'
    public_key_path = SCRIPT_DIR / 'public_key'
    sig_path = SCRIPT_DIR / 'sig'

    data = read_binary(data_file)

    # generate signature
    public_key, signature = generate_key_signature(data)
    write_public_key_openssh(public_key_path, public_key)
    write_binary(sig_path, signature)

    public_key = read_public_key_openssh(public_key_path)
    signature = read_binary(sig_path)
    public_key.verify(signature, data, hashes.SHA1())


if __name__ == "__main__":
    main()
