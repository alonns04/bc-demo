import streamlit as st
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# Función para verificar la firma ECC sobre un mensaje hash
def verify_signature(public_key_pem, signature, message_hash):
    # Cargar la clave pública
    public_key = serialization.load_pem_public_key(public_key_pem.encode())

    # Verificar la firma
    try:
        # Decodificar la firma para obtener r y s
        r, s = decode_dss_signature(signature)
        public_key.verify(
            signature,
            message_hash.encode(),
            ec.ECDSA(hashes.SHA3_256())
        )
        return True
    except Exception as e:
        return False

# Interfaz de la aplicación Streamlit
st.title("Verificación de Firma ECC sobre Hash SHA3-256")

# Inputs del usuario
public_key_pem = st.text_area("Ingresa la clave pública en formato PEM", height=150)
signature = st.text_area("Ingresa la firma (en formato hexadecimal)", height=150)
message_hash = st.text_input("Ingresa el hash SHA3-256 del mensaje")

# Botón para verificar
if st.button("Verificar firma"):
    if not public_key_pem or not signature or not message_hash:
        st.error("Por favor, completa todos los campos.")
    else:
        try:
            # Convertir la firma hexadecimal a bytes
            signature_bytes = bytes.fromhex(signature)

            # Verificar la firma
            if verify_signature(public_key_pem, signature_bytes, message_hash):
                st.success("La firma es válida.")
            else:
                st.error("La firma no es válida.")
        except Exception as e:
            st.error(f"Ocurrió un error: {e}")
