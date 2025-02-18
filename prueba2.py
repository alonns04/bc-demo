from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# 1. Generar una clave privada para firmar
private_key = ec.generate_private_key(ec.SECP256R1())  # Usamos EC con secp256r1
public_key = private_key.public_key()  # Obtenemos la clave pública


# 2. Mensaje a firmar
message = b"Este es un mensaje importante para firmar"
message_hash = hashes.Hash(hashes.SHA3_256())  # Usamos SHA3-256 en lugar de SHA256
message_hash.update(message)
message_digest = message_hash.finalize()

# 3. Firmar el mensaje
signature = private_key.sign(message_digest, ec.ECDSA(hashes.SHA3_256()))

# 4. Convertir la clave pública a formato PEM (esto es lo que enviarías para la verificación)
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 5. Verificación de la firma usando la clave pública
try:
    public_key.verify(signature, message_digest, ec.ECDSA(hashes.SHA3_256()))
    print("La firma es válida.")
except Exception as e:
    print("La firma no es válida:", e)

# Mostrar la clave pública en formato PEM
print("\nClave pública en formato PEM:")
print(public_key_pem.decode())
