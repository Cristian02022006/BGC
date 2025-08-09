from customtkinter import CTk, CTkFrame, CTkEntry, CTkLabel, CTkButton, CTkImage, CTkComboBox
from PIL import Image
import os
from plyer import notification
import threading
import mysql.connector
import pymysql
from googletrans import Translator 
from tkinter import filedialog
from scapy.all import sniff, IP
from datetime import datetime, timedelta
from collections import defaultdict
import time

# ------------ CONFIGURA ESTOS DATOS CON LOS TUYOS --------------------
AWS_ENDPOINT = "database-proyecto-prueba.cdye4eomwbfz.us-east-2.rds.amazonaws.com"   # Coloca el endpoint que te proporciona AWS para tu base de datos RDS
PORT=3306
MYSQL_USER = "cris"
MYSQL_PASSWORD = "crisvg06."   # Coloca la contraseña de tu usuario MySQL
MYSQL_DATABASE = "anomalias"   # Coloca el nombre de tu base de datos MySQL

# Conexión
connection = pymysql.connect(
    host=AWS_ENDPOINT,
    port=PORT,
    user=MYSQL_USER,
    password=MYSQL_PASSWORD,
    database=MYSQL_DATABASE
)

# Variable global para almacenar el ID del usuario actualmente logeado
current_user_id = None

# ---------------------------------------------------------------------

# --- Configuración de Idiomas ---

# Idioma actual de la aplicación. Por defecto: español.
idioma_actual = 'es' # Usaremos códigos de idioma de googletrans (ej. 'es', 'en', 'fr', 'zh-cn', 'de')
translator = Translator() # Inicializa el traductor globalmente

def T(text_to_translate, *args):
    """
    Función de traducción: ahora traduce el texto directamente usando googletrans.
    Se asume que 'text_to_translate' es el texto original en español.
    """
    try:
        translated_text = translator.translate(text_to_translate, dest=idioma_actual, src='es').text
        return translated_text.format(*args) if args else translated_text
    except Exception as e:
        print(f"Error al traducir '{text_to_translate}' con googletrans: {e}. Se devuelve el texto original.")
        return text_to_translate.format(*args) if args else text_to_translate # Devuelve el texto original en caso de error
# Diccionario global para mantener referencias a los diferentes frames de la aplicación.
app_frames = {}
# Variable para mantener una referencia al frame actual visible.
current_active_frame_name = None

def guardar_paquete(pkt):
    """
    Guarda los detalles de un paquete de red en la tabla 'paquetes' de la base de datos MySQL.
    Asegura que la tabla 'paquetes' exista con la estructura definida por el usuario,
    incluyendo la asignación al usuario logeado.
    """
    global current_user_id # Acceder a la variable global

    if IP in pkt:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        # Mapea los números de protocolo a nombres comunes.
        protocol = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, str(proto))
        length = len(pkt)
        detectar_anomalias(pkt)
        try:
            conexion = mysql.connector.connect(
                host=AWS_ENDPOINT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DATABASE
            )
            cursor = conexion.cursor()
            # Crear la tabla 'paquetes' si no existe, con la estructura exacta del usuario
            # y la columna id_usuario con clave foránea.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS paquetes (
                    id_paquete INT PRIMARY KEY AUTO_INCREMENT,
                    timestamp DATETIME,
                    src_ip VARCHAR(45),
                    dst_ip VARCHAR(45),
                    protocol VARCHAR(20),
                    length INT,
                    id_usuario INT, -- Nueva columna para asignar el paquete a un usuario
                    FOREIGN KEY (id_usuario) REFERENCES usuario (id_usuario)
                    ON DELETE CASCADE
                    ON UPDATE SET NULL
                )
            """)
            # Inserta el paquete en la tabla 'paquetes', incluyendo el id_usuario
            cursor.execute("""
                INSERT INTO paquetes (timestamp, src_ip, dst_ip, protocol, length, id_usuario)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (timestamp, src_ip, dst_ip, protocol, length, current_user_id)) # Pasa current_user_id
            conexion.commit() # Confirma la transacción.
        except Exception as e:
            print("Error guardando paquete:", e)
        finally:
            # Asegura que el cursor y la conexión se cierren.
            if 'cursor' in locals(): cursor.close()
            if 'conexion' in locals() and conexion.is_connected(): conexion.close()


##" reglas para las anomalías"
ult_registroa = defaultdict(dict)
tiempo_esp = timedelta(seconds=30)

registro_tiempos = defaultdict(list)
conteo_destinos = defaultdict(set)
registro_protocolos = defaultdict(set)

UMBRAL_PAQUETES_RAPIDOS = 6  
UMBRAL_DESTINOS = 5


def detectar_anomalias(pkt):
    if IP in pkt:
        ip_origen = pkt[IP].src
        ip_destino = pkt[IP].dst
        protocolo = pkt[IP].proto
        hora_actual = datetime.now()

        # Tiempo
        registro_tiempos[ip_origen].append(hora_actual)
        tiempos = [t for t in registro_tiempos[ip_origen] if (hora_actual - t).seconds < 5]
        registro_tiempos[ip_origen] = tiempos  # actualiza para mantener limpio
        num_pkts = len(tiempos)

        if num_pkts > UMBRAL_PAQUETES_RAPIDOS and verificar_anomalia(ip_origen, "TIEMPO"):
            descripcion = f"La IP {ip_origen} envió {num_pkts} paquetes en un tiempo inusual)."
            guardar_anomalia("TIEMPO", descripcion, "Alta")
            print("[ANOMALÍA – TIEMPO]", descripcion)

            if "historial" in app_frames:
                try:
                    app_frames["historial"].load_events()
                except Exception as e:
                    print("No se pudo recargar historial:", e)

        # Dirección
        conteo_destinos[ip_origen].add(ip_destino)
        destinos_unicos = conteo_destinos[ip_origen]
        num_destinos = len(destinos_unicos)

        if num_destinos > UMBRAL_DESTINOS and verificar_anomalia(ip_origen, "DIRECCIÓN"):
        # Muestra solo los 3 primeros destinos para no saturar la descripción
            primeros_dest = ", ".join(list(destinos_unicos)[:3])
            if num_destinos > 3:
                primeros_dest += " …"

            descripcion = (
                f"La IP {ip_origen} contactó a {num_destinos} destinos diferentes")
            guardar_anomalia("DIRECCIÓN", descripcion, "Media")
            print("[ANOMALÍA – DIRECCIÓN]", descripcion)

            if "historial" in app_frames:
                try:
                    app_frames["historial"].load_events()
                except Exception as e:
                    print("No se pudo recargar historial:", e)

        # Tipo / Protocolo
        registro_protocolos[ip_origen].add(protocolo)
        protocolos_usados = registro_protocolos[ip_origen]

        if len(protocolos_usados) > 1 and verificar_anomalia(ip_origen, "PROTOCOLO"):
            descripcion = (
                f"La IP {ip_origen} usó múltiples protocolos: ")
            guardar_anomalia("PROTOCOLO", descripcion, "Alta")
            print("[ANOMALÍA – PROTOCOLO]", descripcion)

            if "historial" in app_frames:
                try:
                    app_frames["historial"].load_events()
                except Exception as e:
                    print("No se pudo recargar historial:", e)


def iniciar_sniffing():
    """
    Inicia la captura de paquetes de red de forma continua.
    Cada paquete capturado es procesado por la función 'guardar_paquete'.
    """
    sniff(prn=guardar_paquete, store=False)



def verificar_anomalia(ip, tipo):
    ahora = datetime.now()
    ultima = ult_registroa[ip].get(tipo)
    if not ultima or (ahora - ultima) > tiempo_esp:
        ult_registroa[ip][tipo] = ahora
        return True
    return False

# --- Database Functions ---
def guardar_anomalia(tipo_anomalia, descripcion, severidad):
    """
    Guarda los detalles de una anomalía detectada en la base de datos MySQL.
    Se conecta a la base de datos RDS de AWS utilizando las credenciales definidas.
    Asigna la anomalía al usuario actualmente logeado.
    """
    global current_user_id # Acceder a la variable global
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conexion = mysql.connector.connect(
            host=AWS_ENDPOINT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE
        )
        cursor = conexion.cursor()

        # Inserta la anomalía en la tabla, incluyendo el id_usuario
        cursor.execute(
            "INSERT INTO anomalias (tipo_anomalia, timestamp, descripcion, severidad, id_usuario) VALUES (%s, %s, %s, %s, %s)",
            (tipo_anomalia, timestamp, descripcion, severidad, current_user_id)
        )
        conexion.commit()
        print(f"[REGISTRO] Anomalía guardada: {tipo_anomalia} - {descripcion}")


        notification.notify(
            title="BGC - Análisis de Red",
            message=f"Anomalía Detectada\n{tipo_anomalia}: {descripcion}",
            timeout=10
        )

    except mysql.connector.Error as err:
        print(f"[ERROR] No se pudo guardar la anomalía: {err}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conexion' in locals() and conexion.is_connected():
            conexion.close()

def detectar_anomalias_con_sql(cursor):
    """
    Detecta y registra anomalías usando consultas SQL.
    """
    
    # 1. Detección de anomalías de tiempo con SQL
    print("Buscando anomalías de tiempo con SQL...")
    
    # Consulta SQL para encontrar IPs con muchos paquetes en poco tiempo
    sql_tiempo = """
    SELECT src_ip, COUNT(*) AS num_paquetes, TIMESTAMPDIFF(SECOND, MIN(timestamp), MAX(timestamp)) AS duracion_segundos
    FROM paquetes
    GROUP BY src_ip
    HAVING COUNT(*) > 4 AND duracion_segundos < 5;
    """
    
  
    # Puedes añadir aquí las consultas para 'DIRECCIÓN' y 'PROTOCOLO'
    # 2. Detección de anomalías de dirección con SQL
    print("Buscando anomalías de dirección con SQL...")
    sql_direccion = """
    SELECT src_ip, COUNT(DISTINCT dst_ip) AS num_destinos_unicos
    FROM paquetes
    GROUP BY src_ip
    HAVING COUNT(DISTINCT dst_ip) > 3;
    """
    

    
    # 3. Detección de anomalías de protocolo con SQL
    print("Buscando anomalías de protocolo con SQL...")
    sql_protocolo = """
    SELECT src_ip, COUNT(DISTINCT protocol) AS num_protocolos
    FROM paquetes
    GROUP BY src_ip
    HAVING COUNT(DISTINCT protocol) > 1;
    """


# --- Network Monitoring Functions ---
def es_anomalia(pkt):
    """
    Analiza un paquete de red para detectar patrones inusuales.
    Actualmente, marca como anomalía cualquier protocolo que no sea TCP, UDP, DNS o ICMP.
    """
    try:
        # Verifica si la capa IP existe en el paquete antes de intentar acceder a sus atributos.
        if hasattr(pkt, 'ip'):
            protocolo = pkt.highest_layer # Obtiene el protocolo de capa más alta.
            src = pkt.ip.src # Dirección IP de origen.
            dst = pkt.ip.dst # Dirección IP de destino.
            # Define una lista de protocolos "normales".
            if protocolo not in ['TCP', 'UDP', 'DNS', 'ICMP']:
                # El mensaje retornado aquí estará en el idioma actual de la aplicación.
                # Será traducido a inglés antes de guardarse en la DB.
                return T("Protocolo inusual: {}", protocolo), src, dst # Usamos T() para traducir
        return None # No es una anomalía o el paquete no tiene capa IP.
    except AttributeError:
        # Maneja casos donde una capa o atributo esperado no existe en el paquete.
        return None
    except Exception as e:
        # Captura cualquier otra excepción inesperada durante el procesamiento del paquete.
        print(f"Error procesando paquete: {e}")
        return None

def notificar_usuario(titulo, mensaje):
    """
    Muestra una notificación emergente en el sistema operativo del usuario.
    """
    notification.notify(title=titulo, message=mensaje, timeout=5)

# Lista global para almacenar los mensajes de notificación que se mostrarán en la GUI.
notificaciones_lista = []


# --- Función para la Gestión de Frames (Interfaces) ---
def show_frame(frame_name):
    """
    Oculta todos los frames de la aplicación y muestra solo el frame especificado.
    Esto permite cambiar entre las diferentes interfaces de usuario.
    """
    global current_active_frame_name
    for frame in app_frames.values():
        frame.grid_forget() # Oculta el frame de la grilla.
    # Muestra el frame deseado, asignándole el mismo espacio en la grilla (columna 0, fila 0).
    app_frames[frame_name].grid(column=0, row=0, sticky='nsew', padx=0, pady=0)
    current_active_frame_name = frame_name

    # Si estamos mostrando el historial, recargar los eventos y paquetes
    if frame_name == "historial":
        if hasattr(app_frames[frame_name], 'load_events'):
            app_frames[frame_name].load_events()
        if hasattr(app_frames[frame_name], 'load_paquetes'):
            app_frames[frame_name].load_paquetes()


def reconstruir_interfaz_actual():
    global current_active_frame_name
    """
    Vuelve a llamar a la función que construye la interfaz actualmente visible
    para refrescar todos los textos después de un cambio de idioma.
    """
    if current_active_frame_name:
        # Destruir el frame actual para forzar su recreación con el nuevo idioma
        if current_active_frame_name in app_frames:
            app_frames[current_active_frame_name].destroy()
            del app_frames[current_active_frame_name] # Eliminar la referencia antigua

        # Reconstruye según el frame activo
        if current_active_frame_name == "principal":
            interfaz_principal()
        elif current_active_frame_name == "usuario":
            interfaz_usuario()
        elif current_active_frame_name == "historial":
            interfaz_historial()
        elif current_active_frame_name == "soporte":
            interfaz_soporte()
        elif current_active_frame_name == "configuracion":
            interfaz_configuracion()

         # Después de recrear, mostrar el frame nuevamente
        app_frames[current_active_frame_name].grid(column=0, row=0, sticky='nsew', padx=0, pady=0)
        app_frames[current_active_frame_name].grid(column=0, row=0, sticky='nsew', padx=0, pady=0)


def actualizar_idioma(nuevo_idioma_seleccionado):
    """
    Cambia el idioma global y reconstruye la interfaz actual para aplicar los cambios.
    """
    global idioma_actual
    # Mapea el texto del ComboBox a la clave del código de idioma de googletrans.
    if nuevo_idioma_seleccionado == "Español":
        idioma_actual = 'es'
    elif nuevo_idioma_seleccionado == "Inglés (Británico)":
        idioma_actual = 'en' # googletrans usa 'en' para inglés general
    elif nuevo_idioma_seleccionado == "Francés":
        idioma_actual = 'fr'
    elif nuevo_idioma_seleccionado == "Chino":
        idioma_actual = 'zh-cn' # chino simplificado
    elif nuevo_idioma_seleccionado == "Alemán":
        idioma_actual = 'de'
    
    print(f"Idioma cambiado a: {idioma_actual}")
    reconstruir_interfaz_actual()

    # Destruir todas las interfaces actuales
    for frame_name in list(app_frames.keys()):
        if frame_name != "login": # No destruir el frame de login
            if frame_name in app_frames:
                app_frames[frame_name].destroy()
                del app_frames[frame_name]

    # Crear todas las interfaces
    interfaz_principal()
    interfaz_usuario()
    interfaz_historial()
    interfaz_soporte()
    interfaz_configuracion()

    # Mostrar la interfaz activa en la que se está, o mostrar la de configuracion
    if current_active_frame_name in app_frames:
        app_frames[current_active_frame_name].grid(column=0, row=0, sticky='nsew')
        if current_active_frame_name == "historial":
            if hasattr(app_frames["historial"], 'load_events'):
                app_frames["historial"].load_events()
    else:
        show_frame("principal")

img_act = None
label_usup = None
label_usupu = None
label_usuh = None
label_usus = None
label_usuc = None

# --- Interfaz de Inicio de Sesión ---
def iniciar_sesion():
    """
    Valida el usuario y contraseña contra la tabla `usuario` en la base de datos.
    Si las credenciales son correctas, cambia a la interfaz principal y guarda el ID del usuario.
    """
    global current_user_id
    entered_username = usuario_entry.get()
    entered_password = contrasenna_entry.get()

    # Encriptar la contraseña ingresada con SHA256 antes de la comparación.
    # El método .encode('utf-8') es necesario para convertir la cadena en bytes.
    hashed_password = hashlib.sha256(entered_password.encode('utf-8')).hexdigest()

    try:
        conexion = mysql.connector.connect(
            host=AWS_ENDPOINT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE
        )
        cursor = conexion.cursor()
        # Asegúrate de que la tabla 'usuario' exista antes de intentar consultarla,
        # ahora con la columna 'contrasena'.
        cursor.execute('''CREATE TABLE IF NOT EXISTS usuario (
                            id_usuario INT PRIMARY KEY,
                            nombre VARCHAR(50) NOT NULL,
                            rol VARCHAR(30),
                            telefono VARCHAR(15),
                            correo VARCHAR(50) UNIQUE NOT NULL,
                            contrasena VARCHAR(255) NOT NULL -- Cambiado de password_hash a contrasena
                        );''')
        conexion.commit() # Confirmar la creación de la tabla si no existía.

         # Consulta para verificar las credenciales, usando la columna 'contrasena'
        # y la contraseña encriptada.
        cursor.execute("SELECT id_usuario FROM usuario WHERE id_usuario = %s AND contrasena = %s",
                       (entered_username, hashed_password))
        user_data = cursor.fetchone()

        if user_data:
            current_user_id = user_data[0] # Almacena el ID del usuario.
            print(f"Inicio de sesión exitoso para el usuario con ID: {current_user_id}")
            # Inicializa las otras interfaces si no están ya en app_frames
            if "principal" not in app_frames:
                interfaz_principal()
            if "usuario" not in app_frames:
                interfaz_usuario()
            if "historial" not in app_frames:
                interfaz_historial()
            if "soporte" not in app_frames:
                interfaz_soporte()
            if "configuracion" not in app_frames:
                interfaz_configuracion()
            show_frame("principal") # Cambia a la interfaz principal.

            threading.Thread(target=iniciar_sniffing, daemon=True).start()

        else:
            CTkLabel(login_frame, text=T('usuario o contraseña incorrectos'), text_color="red", font=('sans serif', 12)).grid(columnspan=2, row=3, padx=4, pady=4)
            print("Intento de inicio de sesión fallido.")

    except mysql.connector.Error as err:
        print(f"Error de base de datos durante el inicio de sesión: {err}")
        CTkLabel(login_frame, text=f"Error de conexión: {err}", text_color="red", font=('sans serif', 12)).grid(columnspan=2, row=3, padx=4, pady=4)
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conexion' in locals() and conexion.is_connected():
            conexion.close()



# ---------------- INTERFAZ PRINCIPAL ------------------------
def interfaz_principal():
    """
    Define y configura la interfaz principal de la aplicación,
    que incluye el menú lateral y el panel de notificaciones en tiempo real.
    """
    global img_act, label_usup
    principal_frame = CTkFrame(root, fg_color='#010101')
    # No lo mostramos aquí, solo lo creamos y lo guardamos. `show_frame` lo mostrará cuando sea necesario.
    app_frames["principal"] = principal_frame # Almacena el frame principal en el diccionario global.

    # Configuración de la grilla para el frame principal (dos columnas: menú y contenido).
    principal_frame.columnconfigure(1, weight=1) # La segunda columna (contenido) se expande.
    principal_frame.rowconfigure(0, weight=1) # La primera fila se expande.

    # Menú lateral (Sidebar)
    menu_frame = CTkFrame(principal_frame, fg_color="#1A1A1A", width=150)
    menu_frame.grid(column=0, row=0, sticky='ns') # Se adhiere al norte y sur.

    try:
        global label_usup
        if img_act is None:
            img = Image.open("Imagenes/usu.png").resize((150, 150))
            img_act = CTkImage(light_image=img, dark_image=img, size=(150, 150))

        label_usup = CTkLabel(master=menu_frame, image=img_act, text="")
        label_usup.pack(pady=(10, 0))
    except Exception as e:
        print("Error cargando icono de usuario:", e)

    try:
        image = Image.open("Imagenes/perfil.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_usuario = CTkImage(light_image=image, dark_image=image, size=(15, 15))
    except Exception as e:
        print("Error cargando icono de usuario:", e)

    try:
        image = Image.open("Imagenes/historial.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_historial = CTkImage(light_image=image, dark_image=image, size=(15, 15))
    except Exception as e:
        print("Error cargando icono de historial:", e)

    try:
        image = Image.open("Imagenes/soporte.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_soporte = CTkImage(light_image=image, dark_image=image, size=(15, 15))
    except Exception as e:
        print("Error cargando icono de soporte:", e)

    try:
        image = Image.open("Imagenes/config2.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_configuracion = CTkImage(light_image=image, dark_image=image, size=(15, 15))
    except Exception as e:
        print("Error cargando icono de configuración:", e)

    try:
        image = Image.open("Imagenes/home.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_home = CTkImage(light_image=image, dark_image=image, size=(15, 15))
    except Exception as e:
        print("Error cargando icono de configuración:", e)


    # Modificar para mostrar el nombre del usuario logeado
    user_name_display = "Usuario" # Default
    if current_user_id:
        print("ID de usuario actual:", current_user_id)    
        try:
            conexion = mysql.connector.connect(host=AWS_ENDPOINT, user=MYSQL_USER, password=MYSQL_PASSWORD, database=MYSQL_DATABASE)
            cursor = conexion.cursor()
            cursor.execute("SELECT nombre FROM usuario WHERE id_usuario = %s", (current_user_id,))
            result = cursor.fetchone()
            if result:
                user_name_display = result[0]
        except Exception as e:
            print(f"Error obteniendo nombre de usuario: {e}")
        finally:
            if 'cursor' in locals(): cursor.close()
            if 'conexion' in locals() and conexion.is_connected(): conexion.close()

    
    CTkLabel(menu_frame, text=user_name_display, font=('sans serif', 20, 'bold')).pack(pady=(20, 10))

# Botones del menú que usan `lambda` para llamar a `show_frame` con el nombre del frame correspondiente.
    CTkButton(menu_frame, text=T('Principal'), image=icon_home ,fg_color="#333333", command=lambda: show_frame("principal")).pack(fill='x', padx=10, pady=5)
    CTkButton(menu_frame, text=T('Usuario'), image=icon_usuario, compound="left", fg_color="#333333", command=lambda: show_frame("usuario")).pack(fill='x', padx=10, pady=5)
    CTkButton(menu_frame, text=T('Historial'), image=icon_historial, compound="left", fg_color="#333333", command=lambda: show_frame("historial")).pack(fill='x', padx=10, pady=5)
    CTkButton(menu_frame, text=T('Soporte'), image=icon_soporte, compound="left", fg_color="#333333", command=lambda: show_frame("soporte")).pack(fill='x', padx=10, pady=5)
    CTkButton(menu_frame, text=T('Configuracion'), image=icon_configuracion, compound="left", fg_color="#333333", command=lambda: show_frame("configuracion")).pack(fill='x', padx=10, pady=5)

    # Panel de Notificaciones (área principal donde se mostrarán las alertas)
    notif_frame = CTkFrame(principal_frame, fg_color="#121212")
    notif_frame.grid(column=1, row=0, sticky='nsew', padx=10, pady=10) # Se expande en todas direcciones.
    notif_frame.columnconfigure(0, weight=1) # La columna del contenido de notificaciones se expande.

    notif_frame.rowconfigure(1, weight=1)
    notif_frame.columnconfigure(0, weight=1)

    mensaje_bienvenida = T("""¡Bienvenido(a) a BGC!
Aplicación que ha sido creada para ayudarte a detectar de forma proactiva anomalías en el tráfico de tu red, identificando patrones inusuales en los paquetes, específicamente en su tipo, dirección y tiempo, los cuales podrían afectar el rendimiento o comprometer la seguridad. 
Con monitoreo en tiempo real y un enfoque inteligente, buscamos fortalecer su estabilidad y protección desde el primer momento.""")

    label_bienvenida = CTkLabel(
        notif_frame,
        text=mensaje_bienvenida,
        wraplength=600,  # Ajusta el ancho máximo del texto antes de que salte línea
        justify="center",
        font=("sans serif", 16),
        text_color="white"
    )
    label_bienvenida.grid(row=1, column=0, sticky="nsew", padx=40, pady=20)
    
    # Almacena el notif_frame directamente como un atributo del principal_frame.
    # Esto facilita su acceso cuando se necesita agregar notificaciones desde el hilo de monitoreo.
    principal_frame.notif_frame = notif_frame


# --- Interfaz de Usuario ---
def interfaz_usuario():
    """
    Define y configura la interfaz de usuario, mostrando información del perfil.
    """
    global imagen_label, label_usupu
    
    usuario_frame = CTkFrame(root, fg_color='#010101')
    app_frames["usuario"] = usuario_frame # Almacena el frame en el diccionario global.
    usuario_frame.grid_forget() # Lo oculta inmediatamente después de crearlo.

    # Configuración de la grilla para el frame de usuario (sidebar + contenido).
    usuario_frame.columnconfigure(1, weight=1)
    usuario_frame.rowconfigure(0, weight=1)

    # Sidebar (menú lateral) - Se crea aquí para cada interfaz secundaria para mantener un menú coherente.
    sidebar = CTkFrame(usuario_frame, fg_color="#0F0F0F", width=180)
    sidebar.grid(row=0, column=0, sticky="ns")
    sidebar.columnconfigure(0, weight=1)

    try:
        logou_image = Image.open("Imagenes/usu.png") 
        logou_ctk = CTkImage(light_image=logou_image, dark_image=logou_image, size=(90, 90))

    except Exception as e:
        print(T("Error cargando icono de usuario:", e))

    try:
        image = Image.open("Imagenes/perfil.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_usuario = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de usuario:", e))

    try:
        image = Image.open("Imagenes/historial.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_historial = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de historial:", e))

    try:
        image = Image.open("Imagenes/soporte.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_soporte = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de soporte:", e))

    try:
        image = Image.open("Imagenes/config2.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_configuracion = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de configuración:", e))

    try:
        image = Image.open("Imagenes/home.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_home = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de configuración:", e))

    label_usupu = CTkLabel(master=sidebar, image=logou_ctk, text="")
    label_usupu.pack(pady=(10, 0))  # Ajusta el margen según lo que necesites

    # Botones del menú para navegar entre interfaces.
    CTkButton(sidebar, text=T('Principal'),image=icon_home ,fg_color="#333333", command=lambda: show_frame("principal")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('Usuario'), image=icon_usuario, compound="left", fg_color="#333333", command=lambda: show_frame("usuario")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('Historial'), image=icon_historial, compound="left", fg_color="#333333", command=lambda: show_frame("historial")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('Soporte'), image=icon_soporte, compound="left", fg_color="#333333", command=lambda: show_frame("soporte")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('Configuracion'), image=icon_configuracion, compound="left", fg_color="#333333", command=lambda: show_frame("configuracion")).pack(fill='x', padx=10, pady=5)
    # Contenido principal del frame de usuario.
    main_content_frame = CTkFrame(usuario_frame, fg_color="#010101")
    main_content_frame.grid(row=0, column=1, sticky='nsew', padx=40, pady=40)
    main_content_frame.columnconfigure(0, weight=1)


    CTkLabel(main_content_frame, text=T("Usuario"), font=('sans serif', 20, 'bold'), text_color="white").grid(row=0, column=0, pady=(10, 5))

    def cambiar_foto():
        global imagen_label, label_usup, label_usupu, img_act
        archivo = filedialog.askopenfilename(title=T("seleccionar_imagen"), filetypes=[("Image files", ".png;.jpg;*.jpeg")])
        if archivo:
            try:
                img = Image.open(archivo).resize((150, 150))
                nueva_img = CTkImage(light_image=img, dark_image=img, size=(150, 150))

                # Actualiza la imagen local de la interfaz usuario
                imagen_label.configure(image=nueva_img)
                imagen_label.image = nueva_img 

                # Actualiza la imagen global para que otras interfaces puedan usarla
                img_act = nueva_img

                if label_usup:
                    label_usup.configure(image=img_act)
                    label_usup.image = img_act

                if label_usupu:
                    label_usupu.configure(image=img_act)
                    label_usupu.image = img_act

                if label_usuh:
                    label_usuh.configure(image=img_act)
                    label_usuh.image = img_act

                if label_usus:
                    label_usuc.configure(image=img_act)
                    label_usuc.image = img_act

                if label_usus:
                    label_usus.configure(image=img_act)
                    label_usus.image = img_act  

                boton_foto.configure(text=T("Actualizar foto"))      

            except Exception as e:
                print(f"Error al cargar la imagen: {e}")

    img = Image.open("Imagenes/usu.png").resize((100, 100))
    perfil_ctk = CTkImage(light_image=img, dark_image=img, size=(100, 100))
    imagen_label = CTkLabel(main_content_frame, image=perfil_ctk, text="")
    imagen_label.grid(row=1, column=0, pady=(5, 10))

    ###CTkButton(main_content_frame, text=T("Añadir foto"), command=cambiar_foto, fg_color="#333333").grid(row=2, column=0, pady=(5, 10))
    boton_foto = CTkButton(main_content_frame, text=T("Añadir foto"), command=cambiar_foto, fg_color="#333333")
    boton_foto.grid(row=2, column=0, pady=(5, 10))

    CTkLabel(main_content_frame, text="Romero", font=('sans serif', 16), text_color="white").grid(row=2, column=0, pady=2)
    CTkLabel(main_content_frame, text="romero@example.com", font=('sans serif', 14), text_color="#AAAAAA").grid(row=3, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("Administrador"), font=('sans serif', 14), text_color="#8de3e5").grid(row=4, column=0, pady=5)


# --- Interfaz de Historial ---
def interfaz_historial():
    """
    en la base de datos.
    """
    global label_usuh, img_act
    historial_frame = CTkFrame(root, fg_color='#010101')
    app_frames["historial"] = historial_frame # Almacena el frame.
    historial_frame.grid_forget() # Lo oculta inicialmente.

    # Configuración de la grilla para el frame de historial.
    historial_frame.columnconfigure(1, weight=1) # Columna de contenido se expande.
    historial_frame.rowconfigure(0, weight=1) # Fila principal se expande.

    # Sidebar (menú lateral) - Se repite por cada interfaz para la navegación.
    sidebar = CTkFrame(historial_frame, fg_color="#0F0F0F", width=180)
    sidebar.grid(row=0, column=0, sticky="ns")
    sidebar.columnconfigure(0, weight=1)

    try:
        global label_usuh
        if img_act is None:
            img = Image.open("Imagenes/usu.png").resize((150, 150))
            img_act = CTkImage(light_image=img, dark_image=img, size=(150, 150))

        label_usuh = CTkLabel(master=sidebar, image=img_act, text="")
        label_usuh.pack(pady=(10, 0))
    except Exception as e:
        print("Error cargando imagen en historial:", e)
    
    try:
        image = Image.open("Imagenes/perfil.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_usuario = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de usuario:", e))

    try:
        image = Image.open("Imagenes/historial.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_historial = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de historial:", e))

    try:
        image = Image.open("Imagenes/soporte.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_soporte = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de soporte:", e))

    try:
        image = Image.open("Imagenes/config2.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_configuracion = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de configuración:", e))

    try:
        image = Image.open("Imagenes/home.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_home = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de configuración:", e))

   
    CTkButton(sidebar, text=T('Principal'),image=icon_home ,fg_color="#333333", command=lambda: show_frame("principal")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('Usuario'), image=icon_usuario, compound="left", fg_color="#333333", command=lambda: show_frame("usuario")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('Historial'), image=icon_historial, compound="left", fg_color="#333333", command=lambda: show_frame("historial")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('Soporte'), image=icon_soporte, compound="left", fg_color="#333333", command=lambda: show_frame("soporte")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('Configuracion'), image=icon_configuracion, compound="left", fg_color="#333333", command=lambda: show_frame("configuracion")).pack(fill='x', padx=10, pady=5)

    # Contenido principal del frame de historial.
    historial_content_frame = CTkFrame(historial_frame, fg_color="#010101")
    historial_content_frame.grid(row=0, column=1, sticky='nsew', padx=20, pady=20)
    historial_content_frame.columnconfigure(0, weight=1)
    historial_content_frame.rowconfigure(2, weight=1) # Permite que el scroll_frame se expanda.

    # Título
    CTkLabel(historial_content_frame,
             text=T("Historial de Anomalías"),
             font=('sans serif', 20, 'bold'),
             text_color='#FFFFFF').grid(row=0, column=0, sticky='w', padx=10, pady=(0, 10))

    # Cuadro de búsqueda (funcionalidad no implementada, es solo visual).
    CTkEntry(historial_content_frame,
             placeholder_text=T('Buscar...'),
             font=('sans serif', 12),
             border_color='#ffffff',
             fg_color="#3B3B3B",
             width=300,
             height=35).grid(row=1, column=0, sticky='w', padx=10, pady=(0, 10))

    # Área scrollable para mostrar eventos (idealmente usar CTkScrollableFrame para más items).
    scroll_frame = CTkFrame(historial_content_frame, fg_color="#121212")
    scroll_frame.grid(row=2, column=0, sticky='nsew', padx=10, pady=10)
    scroll_frame.columnconfigure(0, weight=1)

    def load_events():
        """
        Carga y muestra los eventos (anomalías) desde la base de datos MySQL.
        """
        # Limpia las etiquetas existentes en el scroll_frame antes de cargar nuevas.
        for widget in scroll_frame.winfo_children():
            widget.destroy()

        try:
            conexion = mysql.connector.connect(
                host=AWS_ENDPOINT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DATABASE
            )
            cursor = conexion.cursor()
            # Selecciona las últimas 20 anomalías ordenadas por fecha/hora descendente.
            cursor.execute("SELECT tipo_anomalia, timestamp, descripcion, severidad, origen_ip, destino_ip FROM anomalias ORDER BY timestamp DESC LIMIT 20")
            anomalias = cursor.fetchall()

            if not anomalias:
                CTkLabel(scroll_frame,
                         text=T("No hay anomalías registradas."), # Texto directo para traducir
                         font=('sans serif', 12),
                         text_color='#DDDDDD').grid(row=0, column=0, sticky='w', pady=10, padx=10)
                return

            for idx, (tipo_anomalia_en, timestamp, descripcion_en, severidad, origen_ip, destino_ip) in enumerate(anomalias):
                # Aquí, como los datos de la DB se guardan en inglés, los traducimos al idioma actual de la GUI
                tipo_anomalia_traducida = translator.translate(tipo_anomalia_en, dest=idioma_actual, src='en').text
                descripcion_traducida = translator.translate(descripcion_en, dest=idioma_actual, src='en').text

                CTkLabel(scroll_frame,
                         text=f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}]\n{tipo_anomalia_traducida} → {descripcion_traducida} (Origen: {origen_ip}, Destino: {destino_ip})",
                         font=('sans serif', 12),
                         text_color='#DDDDDD',
                         anchor='w',
                         justify='left',
                         wraplength=scroll_frame._current_width - 20
                         ).grid(row=idx, column=0, sticky='w', pady=4, padx=10)
        except mysql.connector.Error as err:
            CTkLabel(scroll_frame,
                     text=T("Error al cargar historial: {}\nVerifica tus credenciales y endpoint de AWS.", err), # Texto directo para traducir
                     font=('sans serif', 12),
                     text_color='red').grid(row=0, column=0, sticky='w', pady=4, padx=10)
        finally:
            # Cierra el cursor y la conexión a la base de datos.
            if 'cursor' in locals():
                cursor.close()
            if 'conexion' in locals() and conexion.is_connected():
                conexion.close()
    
    # Asociar la función load_events al frame de historial para que reconstruir_interfaz_actual pueda llamarla.
    historial_frame.load_events = load_events

    # Carga los eventos cuando se crea la interfaz de historial.
    # En una aplicación real, esta función podría llamarse cada vez que se muestre el historial.
    load_events()

    # Botón para eliminar el historial (funcionalidad pendiente de implementar).
    CTkButton(historial_content_frame,
              text=T('ELIMINAR HISTORIAL'),
              font=('sans serif', 12),
              border_color="#890000", # Borde rojo.
              fg_color="#3B3B3B",
              hover_color="#7b0000", # Color de hover más oscuro.
              text_color="#ffffff", # Color de texto rojo.
              corner_radius=10,
              border_width=2,
              width=180,
              height=35,
              command=lambda: print("Funcionalidad de eliminar historial pendiente")).grid(row=3, column=0, sticky='e', padx=10, pady=10)

# --- Interfaz de Soporte ---
def interfaz_soporte():
    """
    Define y configura la interfaz de soporte técnico.
    """
    global label_usus, img_act
    soporte_frame = CTkFrame(root, fg_color='#010101')
    app_frames["soporte"] = soporte_frame # Almacena el frame.
    soporte_frame.grid_forget() # Oculta inicialmente.

    soporte_frame.columnconfigure(1, weight=1)
    soporte_frame.rowconfigure(0, weight=1)

    # Sidebar (menú lateral).
    sidebar = CTkFrame(soporte_frame, fg_color="#0F0F0F", width=180)
    sidebar.grid(row=0, column=0, sticky="ns")
    sidebar.columnconfigure(0, weight=1)

    try:
        global label_usus
        if img_act is None:
            img = Image.open("Imagenes/usu.png").resize((150, 150))
            img_act = CTkImage(light_image=img, dark_image=img, size=(150, 150))

        label_usus = CTkLabel(master=sidebar, image=img_act, text="")
        label_usus.pack(pady=(10, 0))
    except Exception as e:
        print("Error cargando imagen en soporte:", e)

    try:
        image = Image.open("Imagenes/perfil.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_usuario = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de usuario:", e))

    try:
        image = Image.open("Imagenes/historial.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_historial = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de historial:", e))

    try:
        image = Image.open("Imagenes/soporte.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_soporte = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de soporte:", e))

    try:
        image = Image.open("Imagenes/config2.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_configuracion = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de configuración:", e))

    try:
        image = Image.open("Imagenes/home.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_home = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de configuración:", e))

    CTkButton(sidebar, text=T('Principal'),image=icon_home ,fg_color="#333333", command=lambda: show_frame("principal")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('Usuario'), image=icon_usuario, compound="left", fg_color="#333333", command=lambda: show_frame("usuario")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('Historial'), image=icon_historial, compound="left", fg_color="#333333", command=lambda: show_frame("historial")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('Soporte'), image=icon_soporte, compound="left", fg_color="#333333", command=lambda: show_frame("soporte")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('Configuracion'), image=icon_configuracion, compound="left", fg_color="#333333", command=lambda: show_frame("configuracion")).pack(fill='x', padx=10, pady=5)
    

    # Contenido principal del frame de soporte.
    main_content_frame = CTkFrame(soporte_frame, fg_color="#010101")
    main_content_frame.grid(row=0, column=1, sticky='nsew', padx=40, pady=40)
    main_content_frame.columnconfigure(0, weight=1)

    CTkLabel(main_content_frame, text=T("Soporte Técnico"), font=('sans serif', 20, 'bold'), text_color="white").grid(row=0, column=0, pady=(10, 5))
    CTkLabel(main_content_frame, text=T("Contactos Soporte"), font=('sans serif', 14), text_color="#AAAAAA").grid(row=1, column=0, pady=5)
    CTkLabel(main_content_frame, text=T("----------------------------------------------------------------"),text_color="#DDDDDD").grid(row=2, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("Nombre: Bárbara Lisset Gonzalez Duran"), font=('sans serif', 14), text_color="#DDDDDD").grid(row=3, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("Email: barbi.lisset10@gmail.com"), font=('sans serif', 14), text_color="#DDDDDD").grid(row=4, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("Teléfono: 2222153877"), font=('sans serif', 14), text_color="#DDDDDD").grid(row=5, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("----------------------------------------------------------------"),text_color="#DDDDDD").grid(row=6, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("Nombre: Ana Gabriela Romero Toriz"), font=('sans serif', 14), text_color="#DDDDDD").grid(row=7, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("Email: gtoriz10v@gmail.com"), font=('sans serif', 14), text_color="#DDDDDD").grid(row=8, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("Teléfono: 2482033049"), font=('sans serif', 14), text_color="#DDDDDD").grid(row=9, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("----------------------------------------------------------------"),text_color="#DDDDDD").grid(row=10, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("Nombre: Cristian Romero Trujeque"), font=('sans serif', 14), text_color="#DDDDDD").grid(row=11, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("Email: romerotrujuquecristian@gmail.com"), font=('sans serif', 14), text_color="#DDDDDD").grid(row=12, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("Teléfono: 2229071425"), font=('sans serif', 14), text_color="#DDDDDD").grid(row=13, column=0, pady=2)

# --- Interfaz de Configuración ---
def interfaz_configuracion():
    """
    Define y configura la interfaz de configuración del sistema,
    incluyendo la opción de cambiar el idioma.
    """
    global label_usuc, img_act
    config_frame = CTkFrame(root, fg_color='#010101')
    app_frames["configuracion"] = config_frame # Almacena el frame.
    config_frame.grid_forget() # Oculta inicialmente.

    config_frame.columnconfigure(1, weight=1)
    config_frame.rowconfigure(0, weight=1)

    # Sidebar (menú lateral).
    sidebar = CTkFrame(config_frame, fg_color="#0F0F0F", width=180)
    sidebar.grid(row=0, column=0, sticky="ns")
    sidebar.columnconfigure(0, weight=1)

    try:
        global label_usuc
        if img_act is None:
            img = Image.open("Imagenes/usu.png").resize((150, 150))
            img_act = CTkImage(light_image=img, dark_image=img, size=(150, 150))

        label_usuc = CTkLabel(master=sidebar, image=img_act, text="")
        label_usuc.pack(pady=(10, 0))
    except Exception as e:
        print("Error cargando imagen en configuración:", e)

    try:
        image = Image.open("Imagenes/perfil.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_usuario = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de usuario:", e))

    try:
        image = Image.open("Imagenes/historial.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_historial = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de historial:", e))

    try:
        image = Image.open("Imagenes/soporte.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_soporte = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de soporte:", e))

    try:
        image = Image.open("Imagenes/config2.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_configuracion = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de configuración:", e))

    try:
        image = Image.open("Imagenes/home.png").resize((15, 15), Image.Resampling.LANCZOS)
        icon_home = CTkImage(light_image=image, dark_image=image, size=(15, 15))  
    except Exception as e:
        print(T("Error cargando icono de configuración:", e))

    
    CTkButton(sidebar, text=T('Principal'),image=icon_home ,fg_color="#333333", command=lambda: show_frame("principal")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('Usuario'), image=icon_usuario, compound="left", fg_color="#333333", command=lambda: show_frame("usuario")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('Historial'), image=icon_historial, compound="left", fg_color="#333333", command=lambda: show_frame("historial")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('Soporte'), image=icon_soporte, compound="left", fg_color="#333333", command=lambda: show_frame("soporte")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('Configuracion'), image=icon_configuracion, compound="left", fg_color="#333333", command=lambda: show_frame("configuracion")).pack(fill='x', padx=10, pady=5)

    # Contenido principal del frame de configuración.
    main_content_frame = CTkFrame(config_frame, fg_color="#010101")
    main_content_frame.grid(row=0, column=1, sticky='nsew', padx=40, pady=40)
    main_content_frame.columnconfigure(0, weight=1)
    main_content_frame.rowconfigure(3, weight=1) # Para que haya espacio si se añaden más opciones

    CTkLabel(main_content_frame, text=T("Configuración"), font=('sans serif', 20, 'bold'), text_color="white").grid(row=0, column=0, pady=(10, 5))
   
    # --- Opción de cambio de idioma ---
    idioma_label = CTkLabel(main_content_frame, text=T("Seleccionar Idioma:"), font=('sans serif', 14), text_color="white")
    idioma_label.grid(row=2, column=0, sticky='w', padx=10, pady=(20, 5))

    # Mapeo inverso de códigos de idioma a nombres de visualización para la inicialización
    lang_display_map = {
        'es': "Español",
        'en': "Inglés (Estadounidense)", # Se asume US English como predeterminado si es 'en'
        'fr': "Francés",
        'zh-cn': "Chino",
        'de': "Alemán"
    }
    initial_language_display = lang_display_map.get(idioma_actual, "Español")


    idioma_combobox = CTkComboBox(main_content_frame, 
                                  values=["Español", "Inglés (Británico)", "Francés", "Chino", "Alemán"],
                                  command=actualizar_idioma,
                                  font=('sans serif', 12),
                                  fg_color="#3B3B3B",
                                  button_color="#555555",
                                  border_color="#ffffff",
                                  border_width=1,
                                  dropdown_fg_color="#3B3B3B",
                                  dropdown_hover_color="#555555",
                                  dropdown_text_color="#FFFFFF")
    idioma_combobox.set(initial_language_display) # Establece el valor inicial.
    idioma_combobox.grid(row=3, column=0, sticky='w', padx=10, pady=(0, 10))

# --- Main Application Setup ---
if __name__ == "__main__":
    root = CTk()
    # Configuración de la ventana principal para la interfaz de login
    root.geometry("500x600+350+20")
    root.minsize(480, 500)
    root.config(bg='#010101')
    root.title(T("BGC - Análisis de Red"))

    # Configuración de la grilla principal de la ventana
    root.grid_columnconfigure(0, weight=1)
    root.grid_rowconfigure(0, weight=1)

    # --- Login Interface Frame ---
    login_frame = CTkFrame(root, fg_color='#010101') # Usamos el nombre 'login_frame' para consistencia
    login_frame.grid(column=0, row=0, sticky='nsew', padx=50, pady=50) # El frame de login se centra
    login_frame.columnconfigure([0, 1], weight=1)
    login_frame.rowconfigure([0, 1, 2, 3, 4, 5], weight=1)
    
    app_frames["login"] = login_frame # Almacena el frame de login en el diccionario

    # Icono y logo (del código de login que proporcionaste)
    image_path = "Imagenes/logo.png"
    ico_path = "Imagenes/logo.ico"
    
    try:
        # Asegurarse de que el archivo .ico exista para el icono de la ventana
        if os.path.exists(image_path) and not os.path.exists(ico_path):
            Image.open(image_path).save(ico_path, format='ICO', sizes=[(140, 140)])
        
        # Cargar logo para mostrar en la interfaz de login
        logo = Image.open(image_path)
        logo_ctk = CTkImage(light_image=logo, dark_image=logo, size=(150, 150))
        CTkLabel(login_frame, image=logo_ctk, text="").grid(columnspan=2, row=0, pady=10)
        
        # Establecer icono de la ventana (solo si el .ico existe)
        if os.path.exists(ico_path):
            root.iconbitmap(ico_path)
    except Exception as e:
        print(T("Error al cargar logo o icono: {}", e)) # Usamos la traducción para el error
        if "logo.ico" in str(e): # Si el error es específicamente por el .ico
            print(T("Error al crear ICO desde PNG: {}", e))


    # Campos de entrada para usuario y contraseña
    usuario_entry = CTkEntry(login_frame,
                             placeholder_text=T('Usuario'),
                             font=('sans serif', 12),
                             border_color='#ffffff',
                             fg_color="#3B3B3B",
                             width=220,
                             height=40)
    usuario_entry.grid(columnspan=2, row=1, padx=4, pady=4)

    contrasenna_entry = CTkEntry(login_frame,
                                 show="*",
                                 placeholder_text=T('Contraseña'),
                                 font=('sans serif', 12),
                                 border_color='#ffffff',
                                 fg_color="#3B3B3B",
                                 width=220,
                                 height=40)
    contrasenna_entry.grid(columnspan=2, row=2, padx=4, pady=4)

    # Botón de inicio de sesión
    bt_iniciar = CTkButton(login_frame,
                           text=T('INICIAR SESIÓN'),
                           font=('sans serif', 12),
                           border_color='#ffffff',
                           fg_color='#3B3B3B',
                           hover_color='#ffffff',
                           corner_radius=12,
                           border_width=2,
                           command=iniciar_sesion) # Llama a la función iniciar_sesion
    bt_iniciar.grid(columnspan=2, row=4, padx=4, pady=4)

    # Mostrar el frame de login al inicio
    show_frame("login")
    
    root.mainloop()