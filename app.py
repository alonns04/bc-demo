import streamlit as st
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

# Función para generar claves ECC
def generar_claves_ecc():
    private_key = ec.generate_private_key(ec.SECP256R1())  # Generar clave privada ECC
    public_key = private_key.public_key()  # Generar clave pública

    # Serializar clave privada en formato PEM
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serializar clave pública en formato PEM
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private_key.decode(), pem_public_key.decode()

# Función para firmar el hash
def firmar_hash(hash_data, private_key_pem):
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    signature = private_key.sign(
        hash_data.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    return signature.hex()

# Separadores entre secciones
def agregar_espacio():
    st.markdown("<br><br><br><br><br><br><br><br><br><br>", unsafe_allow_html=True)
    

# Inicialización de variables en session_state
if "nombre" not in st.session_state:
    st.session_state.nombre = ""
if "apellido" not in st.session_state:
    st.session_state.apellido = ""
if "institucion" not in st.session_state:
    st.session_state.institucion = ""
if "materias" not in st.session_state:
    st.session_state.materias = []
if "hash_alumno" not in st.session_state:
    st.session_state.hash_alumno = ""
if "clave_alumno_privada" not in st.session_state:
    st.session_state.clave_alumno_privada = ""
if "clave_institucion_privada" not in st.session_state:
    st.session_state.clave_institucion_privada = ""
if "firma_alumno" not in st.session_state:
    st.session_state.firma_alumno = ""  # Nueva variable para almacenar la firma del alumno
if "firma_institucion" not in st.session_state:
    st.session_state.firma_institucion = ""  # Nueva variable para almacenar la firma de la institución

# Función para generar el hash del alumno
def generar_hash_alumno():
    datos_alumno = {
        "nombre": st.session_state.nombre,
        "apellido": st.session_state.apellido,
        "institucion": st.session_state.institucion,
        "materias": st.session_state.materias
    }
    json_datos = json.dumps(datos_alumno)
    return hashlib.sha3_256(json_datos.encode()).hexdigest()

# UI para la sección en una sola página
st.title("1º Institución")
st.write("Generación del analítico y su hash por parte de la institución.")

# Formulario de datos del alumno
with st.form("form_alumno"):
    st.text_input("Nombre:", value=st.session_state.nombre, key="nombre")
    st.text_input("Apellido:", value=st.session_state.apellido, key="apellido")
    st.text_input("Institución:", value=st.session_state.institucion, key="institucion")
    
    # Espacio reservado para agregar materias dinámicamente
    st.subheader("Materias y Notas")
    
    for i, materia in enumerate(st.session_state.materias):
        col1, col2, col3 = st.columns([4, 2, 1])
        with col1:
            materia["nombre"] = st.text_input(f"Materia {i+1}", materia["nombre"], key=f"materia_{i}")
        with col2:
            materia["nota"] = st.text_input(f"Nota {i+1}", str(materia["nota"]), key=f"nota_{i}")
        with col3:
            if st.form_submit_button(f"❌ Eliminar {i+1}") :
                st.session_state.materias.pop(i)
                st.rerun()  # 🔹 Recargar la página

    # Botón para enviar el formulario
    submitted = st.form_submit_button("Generar Hash")

# Botón para agregar materias (debe estar FUERA del formulario)
if st.button("➕ Agregar Materia"):
    st.session_state.materias.append({"nombre": "", "nota": 0.0})
    st.rerun()  # Recargar la página

# Procesar el hash solo si el formulario fue enviado
if submitted:
    st.session_state.hash_alumno = generar_hash_alumno()

# Mostrar los datos ingresados y el hash
st.subheader("Datos Ingresados:")
st.json({
    "nombre": st.session_state.nombre,
    "apellido": st.session_state.apellido,
    "institucion": st.session_state.institucion,
    "materias": st.session_state.materias
})

if st.session_state.hash_alumno:
    st.subheader("Hash SHA3-256:")
    st.code(st.session_state.hash_alumno, language="text")




# Uso de la función para separar secciones
agregar_espacio()



st.title("2º Alumno")
st.write("Verificación de su propio analítico y firma con su clave privada.")

# Procesar el hash solo si el formulario fue enviado
if submitted:
    st.session_state.hash_alumno = generar_hash_alumno()

# Mostrar los datos ingresados y el hash
st.subheader("Datos Ingresados:")
st.json({
    "nombre": st.session_state.nombre,
    "apellido": st.session_state.apellido,
    "institucion": st.session_state.institucion,
    "materias": st.session_state.materias
})

if st.session_state.hash_alumno:
    st.subheader("Hash SHA3-256:")
    st.code(st.session_state.hash_alumno, language="text")


# Generar la clave ECC para el alumno
if not st.session_state.clave_alumno_privada:
    private_key, public_key = generar_claves_ecc()
    st.session_state.clave_alumno_privada = private_key  # Guardar clave privada del alumno

# Verificar si ya se firmó el hash y si no, firmarlo
if not st.session_state.firma_alumno and st.session_state.hash_alumno:
    st.session_state.firma_alumno = firmar_hash(st.session_state.hash_alumno, st.session_state.clave_alumno_privada)


# Mostrar la clave privada del alumno y la pública derivada
st.subheader("Clave ECC Privada del Alumno:")
clave_privada = st.text_area("Clave Privada (modificable)", st.session_state.clave_alumno_privada, height=200)

clave_privada_bytes = clave_privada.encode()
if clave_privada_bytes:
    try:
        private_key_obj = serialization.load_pem_private_key(clave_privada_bytes, password=None)
        public_key_obj = private_key_obj.public_key()
        derived_public_key = public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        st.subheader("Clave ECC Pública Derivada del Alumno:")
        st.code(derived_public_key.decode(), language="text")
    except Exception as e:
        st.error(f"Error al derivar la clave pública: {str(e)}")


# Mostrar la firma del alumno
if st.session_state.firma_alumno:
    st.subheader("Firma del Alumno sobre el Hash:")
    st.code(st.session_state.firma_alumno, language="text")




# Uso de la función para separar secciones
agregar_espacio()





# UI para la sección de firma de la institución
st.title("3º Institución")
st.write("Confirma que el alumno firmó el hash correcto. Luego, reafirma la validez haciendo uso de su clave privada.")

# Mostrar los datos ingresados y el hash
st.subheader("Datos Ingresados:")
st.json({
    "nombre": st.session_state.nombre,
    "apellido": st.session_state.apellido,
    "institucion": st.session_state.institucion,
    "materias": st.session_state.materias
})

if st.session_state.hash_alumno:
    st.subheader("Hash SHA3-256:")
    st.code(st.session_state.hash_alumno, language="text")

# Mostrar la firma del alumno
if st.session_state.firma_alumno:
    st.subheader("Firma del Alumno sobre el Hash:")
    st.code(st.session_state.firma_alumno, language="text")

# Generar la clave ECC para la institución (solo una vez)
if not st.session_state.clave_institucion_privada:
    clave_institucion_privada, clave_institucion_publica = generar_claves_ecc()
    st.session_state.clave_institucion_privada = clave_institucion_privada  # Guardar clave privada de la institución

# Mostrar la clave privada de la institución y la pública derivada
st.subheader("Clave ECC Privada de la Institución:")
clave_institucion_privada_area = st.text_area("Clave Privada (modificable)", 
                                              st.session_state.clave_institucion_privada, 
                                              height=200,
                                              key="clave_institucion_privada_area")

clave_institucion_privada_bytes = clave_institucion_privada_area.encode()
if clave_institucion_privada_bytes:
    try:
        private_key_obj = serialization.load_pem_private_key(clave_institucion_privada_bytes, password=None)
        public_key_obj = private_key_obj.public_key()
        derived_public_key_institucion = public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        st.subheader("Clave ECC Pública Derivada de la Institución:")
        st.code(derived_public_key_institucion.decode(), language="text")
    except Exception as e:
        st.error(f"Error al derivar la clave pública: {str(e)}")

# Verificar si ya se firmó la firma del alumno y si no, firmarla con la clave de la institución
if not st.session_state.firma_institucion and st.session_state.firma_alumno:
    st.session_state.firma_institucion = firmar_hash(st.session_state.firma_alumno, st.session_state.clave_institucion_privada)

# Mostrar la firma de la institución
if st.session_state.firma_institucion:
    st.subheader("Firma de la Institución sobre la Firma del Alumno:")
    st.code(st.session_state.firma_institucion, language="text")




# Uso de la función para separar secciones
agregar_espacio()





# UI para la sección 4
st.title("4º Egresado")
st.write("Introducción de un mensaje y firma del hash del mensaje junto con la firma de la institución sobre la firma del alumno.")

# Formulario para el mensaje
message = st.text_area("Introduce un mensaje para firmar:")

# Si el mensaje es ingresado
if message:
    # Crear el diccionario con el mensaje y la firma de la institución sobre la firma del alumno
    mensaje_dict = {
        "mensaje": message,
        "firma": st.session_state.firma_institucion  # Firma de la institución sobre la firma del alumno
    }

    # Crear el hash del diccionario
    mensaje_json = json.dumps(mensaje_dict, sort_keys=True)
    hash_mensaje = hashlib.sha3_256(mensaje_json.encode()).hexdigest()

    # Mostrar el diccionario y su hash
    st.subheader("Diccionario con el Mensaje y Firma de la Institución:")
    st.json(mensaje_dict)
    
    st.subheader("Hash SHA3-256 del Diccionario:")
    st.code(hash_mensaje, language="text")

    # Verificar si el alumno ya firmó el hash
    if not st.session_state.firma_alumno:
        # El alumno firma el hash del diccionario
        st.session_state.firma_alumno = firmar_hash(hash_mensaje, st.session_state.clave_alumno_privada)

    # Mostrar la firma del alumno sobre el hash del diccionario
    if st.session_state.firma_alumno:
        st.subheader("Firma del Alumno sobre el Hash del Diccionario:")
        st.code(st.session_state.firma_alumno, language="text")


# Uso de la función para separar secciones
agregar_espacio()
