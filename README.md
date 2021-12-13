#A1 - Inyección

Las fallas de inyección ocurren cuando se envían datos que no son de confianza a un intérprete como parte de un comando o consulta.Los datos hostiles del atacante pueden engañar al intérprete para que ejecute comandos no deseados o acceda a los datos sin la debida autorización.

Códigos vulnerables
eval(), setTimeout(), setInterval(), Function()

Tipos de inyeccion 

●	Inyección sql

●	Inyección en código

●	Comandos de sistema operativo

●	Inyección Ldap

●	Inyección por xml

●	Inyección por xpath

●	Inyección por ssi

●	Inyección por smtp

●	buffer overflow

EJ: Inyeccion SQL

Un ataque DoS alternativo sería simplemente salir o matar el proceso en ejecución:
 


Respuesta
Interrupción del servicio
 
Remediación
El eval procesa todo incluyendo codigo Java script la remediación mas sencilla fue comentar el codigo y parciar el valor a tipo entero “parseInt”
 

 
Autenticación y gestión de sesiones A2-Broken
En este ataque, un atacante (que puede ser un atacante externo anónimo, un usuario con cuenta propia que puede intentar robar datos de las cuentas o un interno que quiere disfrazar sus acciones) utiliza filtraciones o fallas en las funciones de autenticación o administración de sesiones. hacerse pasar por otros usuarios. Las funciones de la aplicación relacionadas con la autenticación y la gestión de sesiones a menudo no se implementan correctamente, lo que permite a los atacantes comprometer contraseñas, claves o tokens de sesión, o aprovechar otras fallas de implementación para asumir las identidades de otros usuarios.
Los desarrolladores con frecuencia crean esquemas personalizados de autenticación y administración de sesiones, pero construirlos correctamente es difícil. Como resultado, estos esquemas personalizados frecuentemente tienen fallas en áreas como cierre de sesión, administración de contraseñas, tiempos de espera, recordarme, pregunta secreta, actualización de cuenta, etc. Encontrar tales fallas a veces puede ser difícil, ya que cada implementación es única.

Tipos de ataques:

Escenario n. ° 1: los tiempos de espera de las aplicaciones no están configurados correctamente. El usuario usa una computadora pública para acceder al sitio. En lugar de seleccionar "cerrar sesión", el usuario simplemente cierra la pestaña del navegador y se marcha. El atacante usa el mismo navegador una hora más tarde y ese navegador todavía está autenticado.
Escenario n. ° 2: el atacante actúa como intermediario y adquiere la identificación de sesión del usuario del tráfico de red. Luego, usa esta identificación de sesión autenticada para conectarse a la aplicación sin necesidad de ingresar el nombre de usuario y la contraseña.
Escenario n. ° 3: Un intruso o un atacante externo obtiene acceso a la base de datos de contraseñas del sistema. Las contraseñas de los usuarios no están correctamente codificadas, lo que expone la contraseña de todos los usuarios al atacante.

 Protección de las credenciales de usuario


Los problemas de seguridad relacionados con la administración de sesiones se pueden prevenir tomando estas medidas:
●	Las credenciales de autenticación de usuario deben protegerse cuando se almacenan mediante hash o cifrado.

Para protegerlo, maneje el almacenamiento de contraseñas de una manera más segura mediante el uso de cifrado unidireccional con hash de sal como se muestra a continuación:

        // Create user document
        var user = {
            userName: userName,
            firstName: firstName,
            lastName: lastName,
            benefitStartDate: this.getRandomFutureDate(),
            password: bcrypt.hashSync(password, bcrypt.genSaltSync())
Hay aplicaciones como rainbow table stack que busca en diferentes bases de datos puplicas distintos hash (mas habituales) y por medio de un metodo de comparacion se puede saber cual es la password sin hashear.El metodo Salt permite incroporarle un randon mas al hash y asi obtener una barrer contra este tipo de aplicaciones.


        function comparePassword(fromDB, fromUser) {
                    return bcrypt.compareSync(fromDB, fromUser);


El metodo bcrypt va a comparar el hash obtenido por el strig que le envio el usuario con el hash almacenado en la base de datos . Esto obtendra un true/false que le permitira/denegara el acceso. 
 (user-dao.js)
Proteger cookies en tránsito

            cookie: {
            httpOnly: true,
             secure: true
        }
        
En este cado si seteamos httpOnly en true la cokie solo puede ser accedida por http y no por scripting 
Secure true la cookie es enviada al dominio que corresponde pero solo en https
(server.js)

Otra manera de proteger las cookies en tránsito es destruirlas al momento de cerrar sesión 
    this.displayLogoutPage = function(req, res, next) {
        req.session.destroy(function() {
            res.redirect("/");
        });
    };

(session.js)
Adivinar contraseñas

En varios casos el mensaje de aplicacion puede ser una pista para un atacante en el caso de NodeGoat al poner mal un dato el mensaje es “Usuario invalido” de esta manera le estamos diciendo al atancante que el dato que esta mal es el de usuario 
Mensaje correcto
        userDAO.validateLogin(userName, password, function(err, user) {
            var errorMessage = "Acceso inválido. Por favor, inténtelo otra vez.";
(session.js)

Se debe exigir mejor calidad para evitar contraseñas deviles
var PASS_RE =/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/;

        if (!PASS_RE.test(password)) {
            errors.passwordError = "La contraseña debe tener entre 8 y 18 caracteres" +
                "incluyendo números, letras minúsculas y mayúsculas..";
(session.js)


 

 
Secuencias de comandos A3 entre sitios (XSS)
Los defectos de XSS ocurren cuando una aplicación toma datos que no son de confianza y los envía a un navegador web sin la validación o el escape adecuados. XSS permite a los atacantes ejecutar scripts en el navegador de las víctimas, que pueden acceder a las cookies, tokens de sesión u otra información confidencial retenida por el navegador, o redirigir al usuario a sitios maliciosos.

En nodegoat vemos un xss de tipo almacenad. Lo que hace es enviar un xss al servidor se puede ver una salida como si fuesa reflected (el servidor repite los datos maliciosos en una respuesta inmediata a una solicitud HTTP de la víctima) pero además se guarda en algún lado sin sanitizar (el código aun permanece). Lo prevenimos sanitizando este tipo de entrada que envían JavaScripting como la salida. El XSS es aun mas peligroso si nuestra cookie de sesion no utiliza el http Only (Es difícil prevenir todos los defectos XSS en una aplicación. Para ayudar a mitigar el impacto de una falla XSS en su sitio, configure la marca HTTPOnly en la cookie de sesión y cualquier cookie personalizada a la que no se requiera acceder mediante JavaScript.) esto hace que la cookie de sesión sea únicamente utilizado por HTTP. Otra protección es Implementar la política de seguridad de contenido (CSP) básicamente esto hace que le definamos a quienes acceden a los script (podemos poner que accedan los del mismo dominio que la pagina o los de una lista blanca)

El nodegoat utiliza unas paginas que se llaman swing. Poniendo el autoscape un true hace que si usamos las paginas dinámicas como la que hay que usar nos va a escapear el XSS


swig.init ({
    root: __dirname + "/ app / views",
    autoescape: true // valor predeterminado
});
 
autoescape : true
(server.js,)  
Referencias de objetos directos inseguras de A4
Una referencia directa a un objeto ocurre cuando un desarrollador expone una referencia a un objeto de implementación interno, como un archivo, directorio o clave de base de datos. Sin una verificación de control de acceso u otra protección, los atacantes pueden manipular estas referencias para acceder a datos no autorizados.
En el caso de NodeGoat al hacer una consulta sobre alocation en la url podemos ver el parametro de sessionID, simplemnte cambiando el numero de sessionID podemos ver informacion de otro usuario 
imagen
la correccion 
   
this.displayAllocations = function(req, res, next) {
        
// Fix for A4 Insecure DOR -  take user id from session instead of from URL param
        
var userId = req.session.userId;
        
 //var userId = req.params.userId;



 
Configuración incorrecta de A5-Security
Esta vulnerabilidad permite que un atacante acceda a cuentas predeterminadas, páginas no utilizadas, fallas sin parches, archivos y directorios desprotegidos, etc. para obtener acceso no autorizado o conocimiento del sistema.
La configuración incorrecta de la seguridad puede ocurrir en cualquier nivel de una pila de aplicaciones, incluida la plataforma, el servidor web, el servidor de aplicaciones, la base de datos, el marco y el código personalizado.
Los desarrolladores y los administradores del sistema deben trabajar juntos para garantizar que toda la pila esté configurada correctamente.
Un ejemplo de esta vulnerabilidad en el NodeGoat es realizar F5 en la página home Encontramos datos que son interesantes para un atacante Nos muestra el banner del servidor web Ese banner en particular dice powered-bi 
Introducir foto C12 Min05:01

Los que no está diciendo con esto es el framework del lado backend Es el framework Express de node.js
Esto es vulnerabilidad porque da mas informacion de la que deberíamos dar. Un atacante puede buscar vulnerabilidades con la versión del framekork. Su ataque queda mejor enfocado.
En este caso debemos usar una cookie de sesión con un nombre mas genérico

Otro caso en particular es que no se están usando los headers de seguridad. 
Se puede utilizar el framework helmet. Trae protecciones para usar head seguros protegiendo al usuario final. 

npm install helmet --save
"helmet": "^0.9.1",
(package.json)

    // Eliminar el encabezado de respuesta
    app.disable("x-powered-by");

    // Evite la apertura de la página ( secuestro de clics)
    app.use(helmet.xframe());
   
    // almacena en cache y pagina
    app.use(helmet.noCache());

    // Permito cargar recursos solo de lista blanca
    app.use(helmet.csp);

    // solo comunicación HTTPS
    app.use(helmet.hsts());

//Obliga al navegador a usar solo el tipo de contenido establecido en el encabezado de respuesta
   app.use(nosniff());

//uso genérico de cookie
key: "sessionId",
		

(server.js)



Exposición de datos sensibles - A6
Esta vulnerabilidad permite que un atacante acceda a datos confidenciales como tarjetas de crédito, identificaciones fiscales, credenciales de autenticación, etc. para realizar fraudes con tarjetas de crédito, robo de identidad u otros delitos. La pérdida de estos datos puede causar un impacto comercial severo y dañar la reputación. Los datos confidenciales merecen una protección adicional, como el cifrado en reposo o en tránsito, así como precauciones especiales cuando se intercambian con el navegador.

// carga para establecer una conexión HTTPS segura
var fs = require("fs");
var https = require("https");
var path = require("path");
var httpsOptions = {
    //llave privada 	
    key: fs.readFileSync(path.resolve(__dirname, "./artifacts/cert/server.key")),
    //llave cifrada
    cert: fs.readFileSync(path.resolve(__dirname, "./artifacts/cert/server.crt"))

    // protocolo seguro HTTPS
    https.createServer(httpsOptions, app).listen(config.port,  function() {
        console.log("Express https server listening on port " + config.port);
    });
(server.js)
Encriptación de datos del usuario
    // librería cripto para guardar datos confidenciales cifrados
    var crypto = require("crypto");
    var config = require("../../config/config");
    // función para cifrar datos
    var encrypt = function(toEncrypt) {
        var cipher = crypto.createCipher(config.cryptoAlgo, config.cryptoKey);
        return cipher.update(toEncrypt, "utf8", "hex") + cipher.final("hex");
    };
    // función para descifrar datos
    var decrypt = function(toDecrypt) {
        var decipher = crypto.createDecipher(config.cryptoAlgo, config.cryptoKey);
        return decipher.update(toDecrypt, "hex", "utf8") + decipher.final("utf8");
    };
(profile-dao.js)
A7-Control de acceso de nivel de función faltante

La mayoría de las aplicaciones web verifican los derechos de acceso a nivel de función antes de hacer visible esa funcionalidad en la interfaz de usuario. Sin embargo, las aplicaciones deben realizar las mismas comprobaciones de control de acceso en el servidor cuando se accede a cada función.

Dentro de NodeGoat viene seteado 
app.get("/benefits", isLoggedIn, benefitsHandler.displayBenefits);
app.post("/benefits", isLoggedIn, benefitsHandler.updateBenefits);

Esto hace que no se verifique si el usuario que accede a la pagina de beneficios es admin

corregimos
     app.get("/benefits", isLoggedIn, isAdmin, benefitsHandler.displayBenefits);
     app.post("/benefits", isLoggedIn, isAdmin, benefitsHandler.updateBenefits);
     
y comprobar si el usuario tiene derechos de administrador

var SessionHandler = require ("./ sesión");
var isAdmin = sessionHandler.isAdminUserMiddleware;

 

En esta imagen vemos que al usuario por más que modifique la url no le trae información.
A8-Falsificación de solicitud entre sitios (CSRF)
Un ataque CSRF obliga al navegador de una víctima que ha iniciado sesión a enviar una solicitud HTTP falsificada, incluida la cookie de sesión de la víctima y cualquier otra información de autenticación incluida automáticamente, a una aplicación web vulnerable. Esto permite al atacante obligar al navegador de la víctima a generar solicitudes que la aplicación vulnerable procesa como solicitudes legítimas de la víctima.

Es un ataque donde el navegador de la victima es engañado para que emita un comando a una aplicación web vulnerable • La vulnerabilidad es causada debido a que los navegadores incluyen automáticamente información de autenticación del usuario (ID de sesión, dirección IP, credenciales de dominio Windows, ...) en cada pedido HTTP
 
Esta vulnerabilidad esta descontinuada y existe una librería que evita estos ataques. (la mayoría de los framework ya tienen protección contra esta vulnerabilidad)
    
    // Habilita la protección Express csrf
    app.use(csrf());
@@ -120,7 +120,7 @@ MongoClient.connect(config.db, function(err, db) {
        res.locals.csrftoken = req.csrfToken();
        next();
    });

(server.js)


A9-Uso de componentes con vulnerabilidades conocidas
Básicamente este tipo de herramientas en el caso de node.js es validar las dependencias en un Json y cada dependencia tiene sus propias dependencias. Por el ejemplo swing publifile que tiene una vulnerabilidad publicada. 
Lo que debemos hacer es mirar las versiones encontradas en el Jason y corregirlas. Luego volver a generar el proyecto. De esta manera se corrigen las dependencias que tenemos actualmente 
Estas correcciones se pueden resolver con npm Audit 
Prevenimos esta vulnervilidad 
•	No ejecute aplicaciones con privilegios de root
•	Prefiera paquetes que incluyan análisis de código estático. Verifique JSHint / JSLint la configuración para saber qué reglas cumple el código
•	Prefiera paquetes que contengan pruebas unitarias completas y pruebas de revisión para las funciones que utiliza nuestra aplicación
•	Revise el código en busca de cualquier archivo inesperado o acceso a la base de datos
•	Investiga qué tan popular es el paquete, qué otros paquetes lo usan, si el autor ha escrito otros paquetes, etc.
•	Bloquear la versión de los paquetes utilizados
•	Mire los repositorios de Github para ver las notificaciones. Esto nos informará si se descubre alguna vulnerabilidad en el paquete en el futuro.
A10: redireccionamientos y reenvíos no validados
Las aplicaciones web suelen redirigir y reenviar a los usuarios a otras páginas y sitios web, y utilizan datos que no son de confianza para determinar las páginas de destino. Sin la validación adecuada, los atacantes pueden redirigir a las víctimas a sitios de phishing o malware, o utilizar reenvíos para acceder a páginas no autorizadas.

En el caso de NodeGoat cuando nos posicionamos sobre una sección de la página, nos muestra en la parte inferior el link (la muestra a través de un parámetro) donde nos vamos a redirigir.
Estos links nos pueden llevar a un lugar malicioso (malware, pishing) y la remediación es harcodeando la url. 

    app.get("/learn", isLoggedIn, function(req, res, next) {
    /*app.get("/learn", isLoggedIn, function(req, res, next) {
        // Insecure way to handle redirects by taking redirect url from query string
        return res.redirect(req.query.url);
    });
    });*/

<li><a id="learn-menu-link" target="_blank" href="https://www.khanacademy.org/economics-finance-domain/core-finance/investment-vehicles-tutorial/ira-401ks/v/traditional-iras"><i class="fa fa-edit"></i> Learning Resources</a>                    </li>                    {% endif %}                    <li><a id="logout-menu-link" href="/logout"><i class="fa fa-power-off"></i> Logout</a>

(index.js) 




	
 
