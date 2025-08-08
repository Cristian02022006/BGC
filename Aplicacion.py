from customtkinter import CTk, CTkFrame, CTkEntry, CTkLabel, CTkButton, CTkImage, CTkComboBox,CTkToplevel,CTkScrollableFrame
from PIL import Image
import os
import pyshark
from plyer import notification
import threading
import mysql.connector

# ------------ CONFIGURA ESTOS DATOS CON LOS TUYOS --------------------
AWS_ENDPOINT = "database-proyecto-prueba.cdye4eomwbfz.us-east-2.rds.amazonaws.com"   # Coloca el endpoint que te proporciona AWS para tu base de datos RDS
PORT="3306"
MYSQL_USER = "cris"
MYSQL_PASSWORD = "crisvg06."   # Coloca la contraseña de tu usuario MySQL
MYSQL_DATABASE = "gestion_anomalias"   # Coloca el nombre de tu base de datos MySQL
INTERFAZ_RED = "Wi-Fi"   # ¡IMPORTANTE! Cambia esto según el nombre de tu adaptador de red (ej. "Ethernet", "Wi-Fi", "eth0", "wlan0")
# ---------------------------------------------------------------------

# --- Configuración de Idiomas ---
# Diccionario de traducciones para los textos de la interfaz.
# Puedes añadir más idiomas y claves según sea necesario.
TRADUCCIONES = {
    'es': {
        'menu': "Menú",
        'principal': "Principal",
        'usuario': "Usuario",
        'historial': "Historial",
        'soporte': "Soporte",
        'configuracion': "Configuración",
        'notificaciones': "Notificaciones",
        'administrador': "Administrador",
        'anomalia_detectada': "Anomalía detectada",
        'usuario_o_contrasena_incorrectos': "Usuario o contraseña incorrectos. Por favor, intenta de nuevo.",
        'analisis_de_red': "Análisis de Red",
        'iniciar_sesion': "INICIAR SESIÓN",
        'usuario_placeholder': "Usuario",
        'contrasena_placeholder': "Contraseña",
        'historial_anomalias': "Historial de Anomalías",
        'buscar_placeholder': "Buscar...",
        'eliminar_historial': "ELIMINAR HISTORIAL",
        'error_cargar_historial': "Error al cargar historial: {}\nVerifica tus credenciales y endpoint de AWS.",
        'no_anomalias_registradas': "No hay anomalías registradas.",
        'soporte_tecnico': "Soporte Técnico",
        'contacto_soporte': "Para soporte, contacte a:",
        'email_soporte': "Email: support@bgc.com",
        'telefono_soporte': "Teléfono: +52 123 456 7890",
        'configuracion_sistema': "Configuración del Sistema",
        'ajustes_desc': "Aquí podrás ajustar diversas configuraciones.",
        'seleccionar_idioma': "Seleccionar Idioma:",
        'protocolo_inusual': "Protocolo inusual: {}",
        'anomalia_guardada': "Anomalía guardada: {} de {} a {}",
        'error_guardar_anomalia': "Error al guardar anomalía en MySQL: {}",
        'error_monitoreo_red': "Error durante el monitoreo de red: {}",
        'error_cargar_logo': "Error al cargar logo o icono: {}",
        'error_crear_ico': "Error al crear ICO desde PNG: {}",
        'error_cargar_campana': "Error al cargar el ícono de campana: {}",
        'error_cargar_imagen_usuario': "Error al cargar imagen de usuario: {}",
    },
    'en': {
        'menu': "Menu",
        'principal': "Main",
        'usuario': "User",
        'historial': "History",
        'soporte': "Support",
        'configuracion': "Settings",
        'notificaciones': "Notifications",
        'administrador': "Administrator",
        'anomalia_detectada': "Anomaly Detected",
        'usuario_o_contrasena_incorrectos': "Incorrect username or password. Please try again.",
        'analisis_de_red': "Network Analysis",
        'iniciar_sesion': "LOG IN",
        'usuario_placeholder': "Username",
        'contrasena_placeholder': "Password",
        'historial_anomalias': "Anomaly History",
        'buscar_placeholder': "Search...",
        'eliminar_historial': "DELETE HISTORY",
        'error_cargar_historial': "Error loading history: {}\nPlease check your AWS credentials and endpoint.",
        'no_anomalias_registradas': "No anomalies recorded.",
        'soporte_tecnico': "Technical Support",
        'contacto_soporte': "For support, please contact:",
        'email_soporte': "Email: support@bgc.com",
        'telefono_soporte': "Phone: +52 123 456 7890",
        'configuracion_sistema': "System Settings",
        'ajustes_desc': "Here you can adjust various settings.",
        'seleccionar_idioma': "Select Language:",
        'protocolo_inusual': "Unusual protocol: {}",
        'anomalia_guardada': "Anomaly saved: {} from {} to {}",
        'error_guardar_anomalia': "Error saving anomaly to MySQL: {}",
        'error_monitoreo_red': "Error during network monitoring: {}",
        'error_cargar_logo': "Error loading logo or icon: {}",
        'error_crear_ico': "Error creating ICO from PNG: {}",
        'error_cargar_campana': "Error loading bell icon: {}",
        'error_cargar_imagen_usuario': "Error loading user image: {}",
    }
}

# Idioma actual de la aplicación. Por defecto: español.
idioma_actual = 'es'

def T(key, *args):
    """
    Función de traducción: devuelve el texto correspondiente a la clave
    en el idioma actual. Permite formatear cadenas con argumentos.
    """
    text = TRADUCCIONES.get(idioma_actual, {}).get(key, key) # Si no encuentra, devuelve la clave.
    return text.format(*args) if args else text

# Diccionario global para mantener referencias a los diferentes frames de la aplicación.
app_frames = {}
# Variable para mantener una referencia al frame actual visible.
current_active_frame_name = None

# --- Database Functions ---
def guardar_anomalia(mensaje, origen, destino):
    """
    Guarda los detalles de una anomalía detectada en la base de datos MySQL.
    Se conecta a la base de datos RDS de AWS utilizando las credenciales definidas.
    """
    try:
        conexion = mysql.connector.connect(
            host=AWS_ENDPOINT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE
        )
        cursor = conexion.cursor()
        # Crea la tabla 'eventos' si no existe.
        cursor.execute('''CREATE TABLE IF NOT EXISTS eventos (
            id INT AUTO_INCREMENT PRIMARY KEY,
            mensaje TEXT,
            origen VARCHAR(45),
            destino VARCHAR(45),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        # Inserta la anomalía en la tabla.
        cursor.execute(
            "INSERT INTO eventos (mensaje, origen, destino) VALUES (%s, %s, %s)",
            (mensaje, origen, destino)
        )
        conexion.commit() # Confirma la transacción.
        print(T("anomalia_guardada", mensaje, origen, destino))
    except mysql.connector.Error as err:
        print(T("error_guardar_anomalia", err))
    finally:
        # Asegura que la conexión a la base de datos se cierre correctamente.
        if 'conexion' in locals() and conexion.is_connected():
            cursor.close()
            conexion.close()

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
                return T("protocolo_inusual", protocolo), src, dst
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

def agregar_notificacion(frame_destino, mensaje):
    """
    Agrega un mensaje de notificación a la interfaz gráfica en el frame especificado.
    Limita el número de notificaciones mostradas y las actualiza en tiempo real.
    """
    notificaciones_lista.append(mensaje) # Añade el nuevo mensaje a la lista.

    # Limpia las notificaciones existentes en el frame para evitar duplicados y desorden.
    # Excluye los widgets del encabezado (top_frame y su contenido) para no borrarlos.
    for widget in frame_destino.winfo_children():
        # Asumiendo que el top_frame siempre está en la fila 0 y no es un CTkLabel directo.
        # Si la notificación es un CTkLabel y no es parte del encabezado, lo destruimos.
        if isinstance(widget, CTkLabel) and widget.grid_info().get('row') != 0:
            widget.destroy()

    # Muestra las últimas 10 notificaciones (las más recientes primero).
    display_count = 0
    # Itera sobre la lista de notificaciones en orden inverso para mostrar las nuevas arriba.
    for i, msg in enumerate(reversed(notificaciones_lista)):
        if display_count < 10: # Limita el número de notificaciones mostradas.
            # Crea una nueva etiqueta CTkLabel para cada notificación.
            CTkLabel(frame_destino,
                     text=msg,
                     font=('sans serif', 12),
                     text_color='#DDDDDD',
                     anchor='w', # Alinea el texto a la izquierda.
                     justify='left', # Justifica el texto a la izquierda.
                     wraplength=frame_destino._current_width - 40 # Ajusta el salto de línea según el ancho del frame.
                     ).grid(row=i + 1, column=0, sticky='w', padx=20, pady=2) # Coloca la etiqueta en la grilla.
            display_count += 1
        else:
            break # Detiene el bucle si ya se mostraron 10 notificaciones.

def lanzar_monitor_red(notif_frame):
    """
    Inicia el monitoreo de red en un hilo separado para no bloquear la interfaz gráfica.
    Las anomalías detectadas se guardan y se notifican al usuario.
    """
    def monitor():
        try:
            # Inicia la captura de paquetes en vivo en la interfaz de red especificada.
            captura = pyshark.LiveCapture(interface=INTERFAZ_RED)
            for pkt in captura.sniff_continuously(): # Itera indefinidamente sobre los paquetes capturados.
                resultado = es_anomalia(pkt) # Intenta detectar una anomalía.
                if resultado:
                    mensaje, origen, destino = resultado
                    guardar_anomalia(mensaje, origen, destino) # Guarda la anomalía en la base de datos.
                    notificar_usuario(T("anomalia_detectada"), f"{mensaje}\n{origen} → {destino}") # Muestra notificación emergente.
                    # ¡IMPORTANTE! Las actualizaciones de la GUI deben hacerse desde el hilo principal de Tkinter.
                    # `root.after(0, ...)` programa la función `agregar_notificacion` para que se ejecute
                    # tan pronto como el hilo principal esté libre.
                    root.after(0, agregar_notificacion, notif_frame, f"{mensaje}\n{origen} → {destino}")
        except Exception as e:
            print(T("error_monitoreo_red", e))
            # Aquí podrías añadir una notificación al usuario si el monitoreo falla.
    
    # Inicia el hilo de monitoreo. `daemon=True` asegura que el hilo se cierre cuando la aplicación principal se cierre.
    threading.Thread(target=monitor, daemon=True).start()

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

def reconstruir_interfaz_actual():
    global current_active_frame_name
    """
    Vuelve a llamar a la función que construye la interfaz actualmente visible
    para refrescar todos los textos después de un cambio de idioma.
    """
    if current_active_frame_name:
        # Destruir el frame actual para forzar su recreación con el nuevo idioma
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

def actualizar_idioma(nuevo_idioma_seleccionado):
    """
    Cambia el idioma global y reconstruye la interfaz actual para aplicar los cambios.
    """
    global idioma_actual
    # Mapea el texto del ComboBox a la clave del diccionario.
    if nuevo_idioma_seleccionado == "Español":
        idioma_actual = 'es'
    elif nuevo_idioma_seleccionado == "English":
        idioma_actual = 'en'
    
    print(f"Idioma cambiado a: {idioma_actual}")
    reconstruir_interfaz_actual()

    # Destruir todas las interfaces actuales
    for frame_name in list(app_frames.keys()):
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
    else:
        show_frame("configuracion")

# --- Interfaz de Inicio de Sesión ---
def iniciar_sesion():
    """
    MODIFICADO: Esta función ahora directamente cambia a la interfaz principal de la aplicación
    y lanza el monitoreo de red, sin validar usuario ni contraseña.
    """
    # Inicializa las otras interfaces si no están ya en app_frames
    # Esto es importante porque `show_frame` las espera en el diccionario
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
    # Lanza el monitoreo de red, pasándole el frame donde se mostrarán las notificaciones.
    # El notif_frame se almacena como un atributo del principal_frame para facilitar el acceso.
    lanzar_monitor_red(app_frames["principal"].notif_frame)

# ---------------- INTERFAZ DE PRINCIPAL ------------------------
def interfaz_principal():
    """
    Define y configura la interfaz principal de la aplicación,
    que incluye el menú lateral y el panel de notificaciones en tiempo real.
    """
    principal_frame = CTkFrame(root, fg_color='#010101')
    # No lo mostramos aquí, solo lo creamos y lo guardamos. `show_frame` lo mostrará cuando sea necesario.
    app_frames["principal"] = principal_frame # Almacena el frame principal en el diccionario global.

    # Configuración de la grilla para el frame principal (dos columnas: menú y contenido).
    principal_frame.columnconfigure(1, weight=1) # La segunda columna (contenido) se expande.
    principal_frame.rowconfigure(0, weight=1) # La primera fila se expande.

    try:
        logou_image = Image.open("Imagenes/usu.png") 
        logou_ctk = CTkImage(light_image=logou_image, dark_image=logou_image, size=(90, 90))

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


    # Menú lateral (Sidebar)
    menu_frame = CTkFrame(principal_frame, fg_color="#1A1A1A", width=150)
    menu_frame.grid(column=0, row=0, sticky='ns') # Se adhiere al norte y sur.

    label_usu = CTkLabel(master=menu_frame, image=logou_ctk, text="")
    label_usu.pack(pady=(10, 0))  # Ajusta el margen según lo que necesites

    CTkLabel(menu_frame, text="Romero", font=('sans serif', 20, 'bold')).pack(pady=(20, 10))    

# Botones del menú que usan `lambda` para llamar a `show_frame` con el nombre del frame correspondiente.
    CTkButton(menu_frame, text=T('principal'), image=icon_home ,fg_color="#333333", command=lambda: show_frame("principal")).pack(fill='x', padx=10, pady=5)
    CTkButton(menu_frame, text=T('usuario'), image=icon_usuario, compound="left", fg_color="#333333", command=lambda: show_frame("usuario")).pack(fill='x', padx=10, pady=5)
    CTkButton(menu_frame, text=T('historial'), image=icon_historial, compound="left", fg_color="#333333", command=lambda: show_frame("historial")).pack(fill='x', padx=10, pady=5)
    CTkButton(menu_frame, text=T('soporte'), image=icon_soporte, compound="left", fg_color="#333333", command=lambda: show_frame("soporte")).pack(fill='x', padx=10, pady=5)
    CTkButton(menu_frame, text=T('configuracion'), image=icon_configuracion, compound="left", fg_color="#333333", command=lambda: show_frame("configuracion")).pack(fill='x', padx=10, pady=5)

    # Panel de Notificaciones (área principal donde se mostrarán las alertas)
    notif_frame = CTkFrame(principal_frame, fg_color="#121212")
    notif_frame.grid(column=1, row=0, sticky='nsew', padx=10, pady=10) # Se expande en todas direcciones.
    notif_frame.columnconfigure(0, weight=1) # La columna del contenido de notificaciones se expande.

    # Almacena el notif_frame directamente como un atributo del principal_frame.
    # Esto facilita su acceso cuando se necesita agregar notificaciones desde el hilo de monitoreo.
    principal_frame.notif_frame = notif_frame

    # Encabezado del panel de notificaciones (título + icono de campana)
    top_frame = CTkFrame(notif_frame, fg_color="#121212")
    top_frame.grid(row=0, column=0, sticky='ew', pady=(0, 10))
    top_frame.columnconfigure(0, weight=1)

    CTkLabel(top_frame, text=T("notificaciones"), font=("sans serif", 18)).grid(row=0, column=0, sticky='w', padx=10)

    try:
        bell_icon = Image.open("Imagenes/campana2.png").resize((35, 35))
        bell_ctk = CTkImage(light_image=bell_icon, dark_image=bell_icon, size=(35, 35))
        CTkLabel(top_frame, image=bell_ctk, text="").grid(row=0, column=1, sticky='e', padx=10)
    except Exception as e:
        print(T("error_cargar_campana", e))


# --- Interfaz de Usuario ---
def interfaz_usuario():
    """
    Define y configura la interfaz de usuario, mostrando información del perfil.
    """
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

    label_usu = CTkLabel(master=sidebar, image=logou_ctk, text="")
    label_usu.pack(pady=(10, 0))  # Ajusta el margen según lo que necesites


    CTkLabel(sidebar, text="Romero", font=('sans serif', 20, 'bold')).pack(pady=(20, 10))    

    # Botones del menú para navegar entre interfaces.
    CTkButton(sidebar, text=T('principal'),image=icon_home ,fg_color="#333333", command=lambda: show_frame("principal")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('usuario'), image=icon_usuario, compound="left", fg_color="#333333", command=lambda: show_frame("usuario")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('historial'), image=icon_historial, compound="left", fg_color="#333333", command=lambda: show_frame("historial")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('soporte'), image=icon_soporte, compound="left", fg_color="#333333", command=lambda: show_frame("soporte")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('configuracion'), image=icon_configuracion, compound="left", fg_color="#333333", command=lambda: show_frame("configuracion")).pack(fill='x', padx=10, pady=5)
    # Contenido principal del frame de usuario.
    main_content_frame = CTkFrame(usuario_frame, fg_color="#010101")
    main_content_frame.grid(row=0, column=1, sticky='nsew', padx=40, pady=40)
    main_content_frame.columnconfigure(0, weight=1)


    CTkLabel(main_content_frame, text=T("Usuario"), font=('sans serif', 20, 'bold'), text_color="white").grid(row=0, column=0, pady=(10, 5))

    try:
        img = Image.open("Imagenes/usuario.png").resize((100, 100))
        perfil_ctk = CTkImage(light_image=img, dark_image=img, size=(100, 100))
        CTkLabel(main_content_frame, image=perfil_ctk, text="").grid(row=1, column=0, pady=(5, 10))
    except Exception as e:
        print(T("error_cargar_imagen_usuario", e))

    CTkLabel(main_content_frame, text="Romero", font=('sans serif', 16), text_color="white").grid(row=2, column=0, pady=2)
    CTkLabel(main_content_frame, text="romero@example.com", font=('sans serif', 14), text_color="#AAAAAA").grid(row=3, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("administrador"), font=('sans serif', 14), text_color="#8de3e5").grid(row=4, column=0, pady=5)


# --- Interfaz de Historial ---
def interfaz_historial():
    """
    en la base de datos.
    """
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
        logou_image = Image.open("Imagenes/usu.png") 
        logou_ctk = CTkImage(light_image=logou_image, dark_image=logou_image, size=(90, 90))

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

    label_usu = CTkLabel(master=sidebar, image=CTkImage(Image.open("Imagenes/usu.png"), size=(90, 90)), text="")
    label_usu.pack(pady=(10, 0))  # Ajusta el margen según lo que necesites

    CTkLabel(sidebar, text="Romero", font=('sans serif', 20, 'bold')).pack(pady=(20, 10))    
   
    CTkButton(sidebar, text=T('principal'),image=icon_home ,fg_color="#333333", command=lambda: show_frame("principal")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('usuario'), image=icon_usuario, compound="left", fg_color="#333333", command=lambda: show_frame("usuario")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('historial'), image=icon_historial, compound="left", fg_color="#333333", command=lambda: show_frame("historial")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('soporte'), image=icon_soporte, compound="left", fg_color="#333333", command=lambda: show_frame("soporte")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('configuracion'), image=icon_configuracion, compound="left", fg_color="#333333", command=lambda: show_frame("configuracion")).pack(fill='x', padx=10, pady=5)

    # Contenido principal del frame de historial.
    historial_content_frame = CTkFrame(historial_frame, fg_color="#010101")
    historial_content_frame.grid(row=0, column=1, sticky='nsew', padx=20, pady=20)
    historial_content_frame.columnconfigure(0, weight=1)
    historial_content_frame.rowconfigure(2, weight=1) # Permite que el scroll_frame se expanda.

    # Título
    CTkLabel(historial_content_frame,
             text=T("historial_anomalias"),
             font=('sans serif', 20, 'bold'),
             text_color='#FFFFFF').grid(row=0, column=0, sticky='w', padx=10, pady=(0, 10))

    # Cuadro de búsqueda (funcionalidad no implementada, es solo visual).
    campo_busqueda=CTkEntry(historial_content_frame,
             placeholder_text=T('Buscar'),
             font=('sans serif', 12),
             border_color='#ffffff',
             fg_color="#3B3B3B",
             width=300,
             height=35)
    campo_busqueda.grid(row=1, column=0, sticky='w', padx=10, pady=(0, 10))

    # Área scrollable para mostrar eventos (idealmente usar CTkScrollableFrame para más items).
    scroll_frame = CTkScrollableFrame(historial_content_frame, fg_color="#121212", width=600, height=400)
    scroll_frame.grid(row=2, column=0, sticky='nsew', padx=10, pady=10)
    scroll_frame.columnconfigure(0, weight=1)


    campo_busqueda.bind("<KeyRelease>", lambda e: filtrar_eventos(campo_busqueda.get()))

    def confirmar_eliminacion(id, query):
        ventana = CTkToplevel(root)
        ventana.title(T("eliminar_historial"))
        CTkLabel(ventana, text=T("confirmar_eliminacion"), font=('sans serif', 13)).pack(pady=10)
        CTkButton(ventana, text=T("Eliminar"), fg_color="#7b0000",
                  command=lambda: (
                      eliminar_evento(id),
                      ventana.destroy(),
                      filtrar_eventos(query)
                  )).pack(pady=5)
        CTkButton(ventana, text=T("Cancelar"), command=ventana.destroy).pack(pady=5)

    def editar_evento(id, mensaje, origen, destino):
        ventana = CTkToplevel(root)
        ventana.title(T("editar_evento"))
        mensaje_entry = CTkEntry(ventana, placeholder_text="Mensaje", text=mensaje)
        origen_entry = CTkEntry(ventana, placeholder_text="Origen", text=origen)
        destino_entry = CTkEntry(ventana, placeholder_text="Destino", text=destino)
        mensaje_entry.pack(pady=5)
        origen_entry.pack(pady=5)
        destino_entry.pack(pady=5)

        def guardar():
            if not mensaje_entry.get().strip() or not origen_entry.get().strip() or not destino_entry.get().strip():
                CTkLabel(ventana, text=T("Todos los campos son obligatorios"), text_color="red").pack()
                return
            actualizar_evento(id, mensaje_entry.get(), origen_entry.get(), destino_entry.get())
            ventana.destroy()
            filtrar_eventos(campo_busqueda.get())

        CTkButton(ventana, text=T("guardar_cambios"), command=guardar).pack(pady=10)

    def filtrar_eventos(query):
        for widget in scroll_frame.winfo_children():
            widget.destroy()

        eventos = obtener_eventos(filtro=query)

        if not eventos:
            CTkLabel(scroll_frame, text=T("no_anomalias_registradas"),
                     font=('sans serif', 12), text_color="#DDDDDD").grid(row=0, column=0, sticky='w', padx=10, pady=10)
            return

        for idx, (id, mensaje, origen, destino, timestamp) in enumerate(eventos):
            texto = f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}]\n{mensaje}\n{origen} → {destino}"
            CTkLabel(scroll_frame, text=texto,
                     font=('sans serif', 12),
                     text_color="#DDDDDD",
                     anchor='w',
                     justify='left').grid(row=idx, column=0, sticky='w', padx=10, pady=4)

            CTkButton(scroll_frame, text="🗑", width=25,
                      command=partial(confirmar_eliminacion, id, query)).grid(row=idx, column=1, padx=4)

            CTkButton(scroll_frame, text="✏️", width=25,
                      command=partial(editar_evento, id, mensaje, origen, destino)).grid(row=idx, column=2, padx=4)

        # Muestra cuántos resultados se encontraron
        CTkLabel(scroll_frame, text=f"{len(eventos)} eventos mostrados",
                 font=('sans serif', 11), text_color="#AAAAAA").grid(row=idx + 1, column=0, sticky='w', padx=10, pady=(8, 4))

    historial_frame.load_events = lambda: filtrar_eventos("")
    filtrar_eventos("")
    # Botón para eliminar el historial (funcionalidad pendiente de implementar).
    CTkButton(historial_content_frame,
              text=T('eliminar_historial'),
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
        logou_image = Image.open("Imagenes/usu.png") 
        logou_ctk = CTkImage(light_image=logou_image, dark_image=logou_image, size=(90, 90))

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

    label_usu = CTkLabel(master=sidebar, image=logou_ctk, text="")
    label_usu.pack(pady=(10, 0))  # Ajusta el margen según lo que necesites


    CTkLabel(sidebar, text="Romero", font=('sans serif', 20, 'bold')).pack(pady=(20, 10))    

    CTkButton(sidebar, text=T('principal'),image=icon_home ,fg_color="#333333", command=lambda: show_frame("principal")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('usuario'), image=icon_usuario, compound="left", fg_color="#333333", command=lambda: show_frame("usuario")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('historial'), image=icon_historial, compound="left", fg_color="#333333", command=lambda: show_frame("historial")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('soporte'), image=icon_soporte, compound="left", fg_color="#333333", command=lambda: show_frame("soporte")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('configuracion'), image=icon_configuracion, compound="left", fg_color="#333333", command=lambda: show_frame("configuracion")).pack(fill='x', padx=10, pady=5)
    

    # Contenido principal del frame de soporte.
    main_content_frame = CTkFrame(soporte_frame, fg_color="#010101")
    main_content_frame.grid(row=0, column=1, sticky='nsew', padx=40, pady=40)
    main_content_frame.columnconfigure(0, weight=1)

    CTkLabel(main_content_frame, text=T("soporte_tecnico"), font=('sans serif', 20, 'bold'), text_color="white").grid(row=0, column=0, pady=(10, 5))
    CTkLabel(main_content_frame, text=T("contacto_soporte"), font=('sans serif', 14), text_color="#AAAAAA").grid(row=1, column=0, pady=5)
    CTkLabel(main_content_frame, text=T("----------------------------------------------------------------"),text_color="#DDDDDD").grid(row=2, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("email_soporte"), font=('sans serif', 14), text_color="#DDDDDD").grid(row=3, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("telefono_soporte"), font=('sans serif', 14), text_color="#DDDDDD").grid(row=4, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("----------------------------------------------------------------"),text_color="#DDDDDD").grid(row=5, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("email_soporte"), font=('sans serif', 14), text_color="#DDDDDD").grid(row=6, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("telefono_soporte"), font=('sans serif', 14), text_color="#DDDDDD").grid(row=7, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("----------------------------------------------------------------"),text_color="#DDDDDD").grid(row=8, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("email_soporte"), font=('sans serif', 14), text_color="#DDDDDD").grid(row=9, column=0, pady=2)
    CTkLabel(main_content_frame, text=T("telefono_soporte"), font=('sans serif', 14), text_color="#DDDDDD").grid(row=10, column=0, pady=2)

# --- Interfaz de Configuración ---
def interfaz_configuracion():
    """
    Define y configura la interfaz de configuración del sistema,
    incluyendo la opción de cambiar el idioma.
    """
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
        logou_image = Image.open("Imagenes/usu.png") 
        logou_ctk = CTkImage(light_image=logou_image, dark_image=logou_image, size=(90, 90))

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

    label_usu = CTkLabel(master=sidebar, image=logou_ctk, text="")
    label_usu.pack(pady=(10, 0))  # Ajusta el margen según lo que necesites

    CTkLabel(sidebar, text="Romero", font=('sans serif', 20, 'bold')).pack(pady=(20, 10))    
    
    CTkButton(sidebar, text=T('principal'),image=icon_home ,fg_color="#333333", command=lambda: show_frame("principal")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('usuario'), image=icon_usuario, compound="left", fg_color="#333333", command=lambda: show_frame("usuario")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('historial'), image=icon_historial, compound="left", fg_color="#333333", command=lambda: show_frame("historial")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('soporte'), image=icon_soporte, compound="left", fg_color="#333333", command=lambda: show_frame("soporte")).pack(fill='x', padx=10, pady=5)
    CTkButton(sidebar, text=T('configuracion'), image=icon_configuracion, compound="left", fg_color="#333333", command=lambda: show_frame("configuracion")).pack(fill='x', padx=10, pady=5)

    # Contenido principal del frame de configuración.
    main_content_frame = CTkFrame(config_frame, fg_color="#010101")
    main_content_frame.grid(row=0, column=1, sticky='nsew', padx=40, pady=40)
    main_content_frame.columnconfigure(0, weight=1)
    main_content_frame.rowconfigure(3, weight=1) # Para que haya espacio si se añaden más opciones

    CTkLabel(main_content_frame, text=T("configuracion_sistema"), font=('sans serif', 20, 'bold'), text_color="white").grid(row=0, column=0, pady=(10, 5))
    CTkLabel(main_content_frame, text=T("ajustes_desc"), font=('sans serif', 14), text_color="#AAAAAA").grid(row=1, column=0, pady=5)
    
    # --- Opción de cambio de idioma ---
    idioma_label = CTkLabel(main_content_frame, text=T("seleccionar_idioma"), font=('sans serif', 14), text_color="white")
    idioma_label.grid(row=2, column=0, sticky='w', padx=10, pady=(20, 5))

    # Determinar el valor inicial del ComboBox según el idioma actual.
    initial_language_display = "Español" if idioma_actual == 'es' else "English"

    idioma_combobox = CTkComboBox(main_content_frame, 
                                  values=["Español", "English"],
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
    root.title("BGC - Análisis de Red")

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
        print(T("error_cargar_logo", e)) # Usamos la traducción para el error
        if "logo.ico" in str(e): # Si el error es específicamente por el .ico
            print(T("error_crear_ico", e))


    # Campos de entrada para usuario y contraseña
    usuario_entry = CTkEntry(login_frame,
                             placeholder_text=T('usuario_placeholder'),
                             font=('sans serif', 12),
                             border_color='#ffffff',
                             fg_color="#3B3B3B",
                             width=220,
                             height=40)
    usuario_entry.grid(columnspan=2, row=1, padx=4, pady=4)

    contrasenna_entry = CTkEntry(login_frame,
                                 show="*",
                                 placeholder_text=T('contrasena_placeholder'),
                                 font=('sans serif', 12),
                                 border_color='#ffffff',
                                 fg_color="#3B3B3B",
                                 width=220,
                                 height=40)
    contrasenna_entry.grid(columnspan=2, row=2, padx=4, pady=4)

    # Botón de inicio de sesión
    bt_iniciar = CTkButton(login_frame,
                           text=T('iniciar_sesion'),
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