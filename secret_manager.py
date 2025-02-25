# %%
from google.cloud import secretmanager
import base64
from google.cloud import kms


def get_secret(project_id, secret_id):

    # Create a Secrets Manager client
    client = secretmanager.SecretManagerServiceClient()

    name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(name=name)
    secret_value = response.payload.data.decode("UTF-8")

    return secret_value


def encrypt_symmetric(
    project_id: str, location_id: str, key_ring_id: str, key_id: str, plaintext: str
) -> bytes:
    """
    Encrypt plaintext using a symmetric key.

    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
        key_id (string): ID of the key to use (e.g. 'my-key').
        plaintext (string): message to encrypt

    Returns:
        bytes: Encrypted ciphertext.

    """

    # Convert the plaintext to bytes.
    plaintext_bytes = plaintext.encode("utf-8")

    # Optional, but recommended: compute plaintext's CRC32C.
    # See crc32c() function defined below.
    # plaintext_crc32c = crc32c(plaintext_bytes)

    # Create the client.
    client = kms.KeyManagementServiceClient()

    # Build the key name.
    key_name = client.crypto_key_path(
        project_id, location_id, key_ring_id, key_id)

    # Call the API.
    encrypt_response = client.encrypt(
        request={
            "name": key_name,
            "plaintext": plaintext_bytes,
            # "plaintext_crc32c": plaintext_crc32c,
        }
    )

    # Optional, but recommended: perform integrity verification on encrypt_response.
    # For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
    # https://cloud.google.com/kms/docs/data-integrity-guidelines
    # if not encrypt_response.verified_plaintext_crc32c:
    #     raise Exception(
    #         "The request sent to the server was corrupted in-transit.")
    # if not encrypt_response.ciphertext_crc32c == crc32c(encrypt_response.ciphertext):
    #     raise Exception(
    #         "The response received from the server was corrupted in-transit."
    #     )
    # End integrity verification

    print(f"Ciphertext: {base64.b64encode(encrypt_response.ciphertext)}")
    return encrypt_response


def decrypt_symmetric(
    project_id: str, location_id: str, key_ring_id: str, key_id: str, ciphertext: bytes
) -> kms.DecryptResponse:
    """
    Decrypt the ciphertext using the symmetric key

    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
        key_id (string): ID of the key to use (e.g. 'my-key').
        ciphertext (bytes): Encrypted bytes to decrypt.

    Returns:
        DecryptResponse: Response including plaintext.

    """

    # Create the client.
    client = kms.KeyManagementServiceClient()

    # Build the key name.
    key_name = client.crypto_key_path(
        project_id, location_id, key_ring_id, key_id)

    # Optional, but recommended: compute ciphertext's CRC32C.
    # See crc32c() function defined below.
    # ciphertext_crc32c = crc32c(f"{ciphertext!r}")

    # Call the API.
    decrypt_response = client.decrypt(
        request={
            "name": key_name,
            "ciphertext": ciphertext,
            # "ciphertext_crc32c": ciphertext_crc32c,
        }
    )

    # Optional, but recommended: perform integrity verification on decrypt_response.
    # For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
    # https://cloud.google.com/kms/docs/data-integrity-guidelines
    # if not decrypt_response.plaintext_crc32c == crc32c(decrypt_response.plaintext):
    #     raise Exception(
    #         "The response received from the server was corrupted in-transit."
    #     )
    # End integrity verification

    print(f"Plaintext: {decrypt_response.plaintext!r}")
    return decrypt_response


# def crc32c(data: bytes) -> int:
#     """
#     Calculates the CRC32C checksum of the provided data.
#     Args:
#         data: the bytes over which the checksum should be calculated.
#     Returns:
#         An int representing the CRC32C checksum of the provided bytes.
#     """
#     import crcmod  # type: ignore

#     crc32c_fun = crcmod.predefined.mkPredefinedCrcFun("crc-32c")
#     return crc32c_fun(data)

# %%
