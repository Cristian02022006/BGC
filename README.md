BGC-Analisis de Red
Equipo:
- Barbara Lisset Gonzalez Duran
- Ana Gabriela Romero Toriz
- Crisrtian Romero Trujeque
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
DOCUMENTACIÓN DE LA APLICACIÓN
-INTERFAZ DE INICIO DE SESIÓN
Al inicializar la aplicacion se adrira una pantalla de inicio de sesion, donde se validaran los datos dados al usuario tales como su "Nombre de usuario" y "Contraseña,
dichos datos se validaran con los datos insertados por nosotros en la tabla `usuario` en la base de datos.
Si las credenciales son correctas, cambiar la pantalla de inicio a la interfaz principal y se guarda el ID del usuario.
  <img width="1059" height="1082" alt="image" src="https://github.com/user-attachments/assets/3a31d493-e268-4fe3-9e2e-89581e6f2895" />
  
  <img width="2879" height="1532" alt="image" src="https://github.com/user-attachments/assets/b0e1de69-e16b-4ee0-850a-6331d7540958" />

-INTERFAZ PRINCIPAL
En esta pantalla se vizualizara inicialmente nuestro menu (dicho menu se mostrara en todas las interfacez, ya que este sera un menu fijo) en el lado posterior izquierdo, al cual se le agregaron iconos para una mejor interpretación y se facilitara la navegacion,
esto se trabajo con la ayuda de botones que permiten al usuario navegar libremente sobre las demas interfaces, asimismo en esta pantalla se observara una breve bienvenida donde se explicara el proposito
inicial de nuestra aplicacion.
 <img width="895" height="1198" alt="image" src="https://github.com/user-attachments/assets/3ae50ce0-21ce-412d-828b-d193b8352b5a" />
 <img width="1773" height="553" alt="image" src="https://github.com/user-attachments/assets/9103d2f3-a524-4357-8fab-6d89a60d7782" />

 <img width="2877" height="1526" alt="image" src="https://github.com/user-attachments/assets/2456202d-f88e-4008-8286-e3b58421369a" />

-INTERFAZ DE USUARIO
Ya en la interfaz de usuario se vizualiza la información del perfil de dicho usuario (Nombre, Rol y Corre),guardada en la base de datos. En esta pantalla tambien se le permitira al usuario insertar y
seleccionar una imagen al gusto para su foto de perfil, asi como tambien se permitira actualizarla si este lo desea.
 <img width="697" height="977" alt="image" src="https://github.com/user-attachments/assets/407a6081-5ca9-4aa0-b5b8-6aca1fa2b1b4" />
 <img width="1217" height="1328" alt="image" src="https://github.com/user-attachments/assets/cd233db1-4a05-449e-99a3-8fc2f7a7b8e5" />

<img width="2879" height="1505" alt="image" src="https://github.com/user-attachments/assets/8897042c-608e-4b89-b0fc-2e10cce91ec9" />
<img width="2879" height="1516" alt="image" src="https://github.com/user-attachments/assets/03947489-3f11-42ef-8a94-e49c026aaee3" />
<img width="2879" height="1504" alt="image" src="https://github.com/user-attachments/assets/0cee43fc-1205-4c77-bb5d-998f2e86bd67" />
 
-INTERFAZ DE HISTORIAL
En historial, la interfaz es dividida en dos apartados, del lado izquierdo se mostraran las anomalias registradas en la base de datos, estas con base a las reglas de tiempo, protocolo y dirección.
 Reglas:
- Tiempo: Evalúa cuántos paquetes ha enviado una IP de origen en un periodo corto de tiempo, en este caso (5 segundos).
-	Protocolo: Se detecta si una IP ha utilizado más de un tipo de protocolo, ejemplo TCP, UDP, ICMP, entre otros.
-	Dirección: se detecta si una IP de origen está contactando a demasiadas IPs destino diferentes (>3).
 Severidad:
- Tiempo: Catalogada con severidad alta, debido a que puede tirar servicios o saturar la red.
- Protocolo: Severidad alta, ya que si un dispositivo empieza a usar protocolos que normalmente no utiliza, podría ser un intento de evasión de firewall o
un malware que prueba múltiples métodos de comunicación.
- Dirección: Severidad media porque así como puede ser que un dispositivo comprometido esté intentando propagarse,
es decir, cuando un malware infecta un dispositivo y que muchas veces intenta replicarse y enviarse a otros dispositivos en la red,}
también puede ocurrir de forma legítima, como un navegador cargando varios recursos desde distintas IPs.
En este mismo apartado del lado derecho se encontrara el guardado y ejecucion de loa paquetes insertados en la base de datos en tiempo real con el uso de la libreria scapy, con una estructura visible 
de los datos del paquete tales como la hora en que es guardado, si id, protocolo, direccion origen y destino, asi como el tamaño de dicho paquete.
Algunas acciones que podra realizar el usuario en esta ventana son buscar anomalias, ya sea por su tipo de anomalia, su severidad, la fecha y hora en la que se notifico asi como tambien se le permite
borrar el historial de anomalias guardadas en la base de datos.
 <img width="903" height="1229" alt="image" src="https://github.com/user-attachments/assets/52e69d37-4f12-487a-83be-ee04e255b4ff" />
 <img width="1226" height="1051" alt="image" src="https://github.com/user-attachments/assets/a806c946-b3c6-42e5-ae2b-af1b3bdc4a6b" />
 <img width="837" height="1241" alt="image" src="https://github.com/user-attachments/assets/a2a7f6e8-55f4-4e38-a252-d4e772a85c25" />
 <img width="1266" height="1267" alt="image" src="https://github.com/user-attachments/assets/6d4fefc4-24fd-4c18-8519-19c8f51bd329" />
 <img width="774" height="1198" alt="image" src="https://github.com/user-attachments/assets/7215191c-f946-490e-bfd2-e67f5a2140d2" />

 <img width="2879" height="1514" alt="image" src="https://github.com/user-attachments/assets/1e9b405d-0f1e-43e7-adda-37e3c6b9960a" />
 <img width="2879" height="1520" alt="image" src="https://github.com/user-attachments/assets/7764aafc-012b-459d-8c1c-75a06d2ac881" />
 <img width="2862" height="1511" alt="image" src="https://github.com/user-attachments/assets/0b1d7b5b-cc2a-4daf-8ef8-236c543f2894" />
 <img width="2879" height="1513" alt="image" src="https://github.com/user-attachments/assets/8e9d35d4-de81-46a7-ac23-2cb7b153a098" />
 <img width="2867" height="1491" alt="image" src="https://github.com/user-attachments/assets/c6d7156d-0b92-4078-b680-be635b9d5151" />

- INTERFAZ DE SOPORTE
Continuamos con la pantalla de soporte, en esta se encuentran los datos de contacto de nosotros, pues somos los encargados de que nuestra aplicación funcione correctamente,
como se muestra, aparece nuestro nombre, correo y teléfono.
 <img width="1238" height="1275" alt="image" src="https://github.com/user-attachments/assets/4335670b-82e0-49d3-a0db-badf49b26a5d" />
 <img width="1131" height="326" alt="image" src="https://github.com/user-attachments/assets/d880bbd8-d78b-462b-9148-ac004059df54" />

<img width="2879" height="1527" alt="image" src="https://github.com/user-attachments/assets/6b68df85-4427-41ee-97d7-f005f7f284dd" />

- INTERFAZ DE CONFIGURACION
En el apartado de configuración por el momento solo se encuentra la funcionalidad del cambio de idioma, siendo solo 5 (Español, Ingles (Britanico), Aleman, Chino y Frances)
idiomas configurados para la traduccion ya que a futuro pensamos implementar la personalización del tamaño de letra al igual que el cambio de tema de la interfaz.
 <img width="970" height="1197" alt="image" src="https://github.com/user-attachments/assets/900ca40a-8d58-4def-b52e-9468e9876d18" />
 <img width="1227" height="667" alt="image" src="https://github.com/user-attachments/assets/2fec8877-0d4e-472e-8bcf-f364b5367c35" />

 <img width="2879" height="1513" alt="image" src="https://github.com/user-attachments/assets/7090dd80-090b-45f5-be15-0e0313f86e53" />
 








