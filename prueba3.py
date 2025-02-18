from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Función para verificar la firma con SHA3-256
def verificar_firma(public_key_pem, hash_data, firma_hex):
    # Cargar la clave pública desde el formato PEM
    public_key = serialization.load_pem_public_key(public_key_pem.encode())

    # Convertir la firma hexadecimal a bytes
    firma = bytes.fromhex(firma_hex)

    try:
        # Verificar la firma usando la clave pública y el hash con SHA3-256
        public_key.verify(
            firma,
            hash_data.encode(),
            ec.ECDSA(hashes.SHA3_256())
        )
        return True  # Firma válida
    except InvalidSignature:
        return False  # Firma inválida

# Ejemplo de uso
public_key_pem = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETmF7Kc2op4kGpa6Zbov/jZhnTFGR
7MPfH5rTdf6fTd91eIwmo9fILB1Xil391sQ8GvcS/j34An1LWOlOVW6Gxw==
-----END PUBLIC KEY-----"""

hash_data = "39f06d87544b959da7b242f78059dc8f4ab6312e8870023e56b0896dcf8c233a"  # Hash proporcionado
firma_hex = "30460221009f585f31d0abff54b21c905bf099f64e76578cb9bd0cd90cce9ddaf739d6f66b022100b44e581ef8e7922b4bb0abae0d67e643bc698ef0567e8cce1310464a3d6ec450"  # Firma proporcionada

# Verificar la firma
es_valida = verificar_firma(public_key_pem, hash_data, firma_hex)
print("La firma es válida:", es_valida)
