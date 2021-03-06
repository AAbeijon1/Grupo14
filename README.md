# NodeGoat

Being lightweight, fast, and scalable, Node.js is becoming a widely adopted platform for developing web applications. This project provides an environment to learn how OWASP Top 10 security risks apply to web applications developed using Node.js and how to effectively address them.

## Getting Started
OWASP Top 10 for Node.js web applications:

### Know it!
[Tutorial Guide](http://nodegoat.herokuapp.com/tutorial) explaining how each of the OWASP Top 10 vulnerabilities can manifest in Node.js web apps and how to prevent it.

### Do it!
[A Vulnerable Node.js App for Ninjas](http://nodegoat.herokuapp.com/) to exploit, toast, and fix. You may like to [set up your own copy](#how-to-set-up-your-copy-of-nodegoat) of the app to fix and test vulnerabilities. Hint: Look for comments in the source code.
##### Default user accounts
The database comes pre-populated with these user accounts created as part of the seed data -
* Admin Account - u:admin p:Admin_123
* User Accounts (u:user1 p:User1_123), (u:user2 p:User2_123)
* New users can also be added using the sign-up page.

## How to Set Up Your Copy of NodeGoat

### OPTION 1 - Run NodeGoat on your machine

1) Install [Node.js](http://nodejs.org/) - NodeGoat requires Node v8 or above

2) Clone the github repository:
   ```
   git clone https://github.com/OWASP/NodeGoat.git
   ```

3) Go to the directory:
   ```
   cd NodeGoat
   ```

4) Install node packages:
   ```
   npm install
   ```

5) Set up MongoDB. You can either install MongoDB locally or create a remote instance:

   * Using local MongoDB:
     1) Install [MongoDB Community Server](https://docs.mongodb.com/manual/administration/install-community/)
     2) Start [mongod](http://docs.mongodb.org/manual/reference/program/mongod/#bin.mongod)

   * Using remote MongoDB instance:
     1) [Deploy a MongoDB Atlas free tier cluster](https://docs.atlas.mongodb.com/tutorial/deploy-free-tier-cluster/) (M0 Sandbox)
     2) [Enable network access](https://docs.atlas.mongodb.com/security/add-ip-address-to-list/) to the cluster from your current IP address
     3) [Add a database user](https://docs.atlas.mongodb.com/tutorial/create-mongodb-user-for-cluster/) to the cluster
     4) Set the `MONGODB_URI` environment variable to the connection string of your cluster, which can be viewed in the cluster's
        [connect dialog](https://docs.atlas.mongodb.com/tutorial/connect-to-your-cluster/#connect-to-your-atlas-cluster). Select "Connect your application",
        set the driver to "Node.js" and the version to "2.2.12 or later". This will give a connection string in the form:
        ```
        mongodb://<username>:<password>@<cluster>/<dbname>?ssl=true&replicaSet=<rsname>&authSource=admin&retryWrites=true&w=majority
        ```
        The `<username>` and `<password>` fields need filling in with the details of the database user added earlier. The `<dbname>` field sets the name of the
        database nodegoat will use in the cluster (eg "nodegoat"). The other fields will already be filled in with the correct details for your cluster.

6) Populate MongoDB with the seed data required for the app:
   ```
   npm run db:seed
   ```
   By default this will use the "development" configuration, but the desired config can be passed as an argument if required.

7) Start the server. You can run the server using node or nodemon:
   * Start the server with node. This starts the NodeGoat application at [http://localhost:4000/](http://localhost:4000/):
     ```
     npm start
     ```
   * Start the server with nodemon, which will automatically restart the application when you make any changes. This starts the NodeGoat application at [http://localhost:5000/](http://localhost:5000/):
     ```
     npm run dev
     ```

#### Customizing the Default Application Configuration
By default the application will be hosted on port 4000 and will connect to a MongoDB instance at localhost:27017. To change this set the environment variables `PORT` and `MONGODB_URI`.

Other settings can be changed by updating the [config file](https://github.com/OWASP/NodeGoat/blob/master/config/env/all.js).


### OPTION 2 - Run NodeGoat on Docker

The repo includes the Dockerfile and docker-compose.yml necessary to set up the app and db instance, then connect them together.

1) Install [docker](https://docs.docker.com/installation/) and [docker compose](https://docs.docker.com/compose/install/) 

2) Clone the github repository:
   ```
   git clone https://github.com/OWASP/NodeGoat.git
   ```

3) Go to the directory:
   ```
   cd NodeGoat
   ```

4) Build the images:
   ```
   docker-compose build
   ```

5) Run the app, this starts the NodeGoat application at http://localhost:4000/:
   ```
   docker-compose up
   ```


### OPTION 3 - Deploy to Heroku

This option uses a free ($0/month) Heroku node server.

Though not essential, it is recommended that you fork this repository and deploy the forked repo.
This will allow you to fix vulnerabilities in your own forked version, then deploy and test it on Heroku.

1) Set up a publicly accessible MongoDB instance:
   1) [Deploy a MongoDB Atlas free tier cluster](https://docs.atlas.mongodb.com/tutorial/deploy-free-tier-cluster/) (M0 Sandbox)
   2) [Enable network access](https://docs.atlas.mongodb.com/security/ip-access-list/#add-ip-access-list-entries) to the cluster from anywhere (CIDR range 0.0.0.0/0)
   3) [Add a database user](https://docs.atlas.mongodb.com/tutorial/create-mongodb-user-for-cluster/) to the cluster

2) Deploy NodeGoat to Heroku by clicking the button below:

   [![Deploy](https://www.herokucdn.com/deploy/button.png)](https://heroku.com/deploy)

   In the Create New App dialog, set the `MONGODB_URI` config var to the connection string of your MongoDB Atlas cluster.
   This can be viewed in the cluster's [connect dialog](https://docs.atlas.mongodb.com/tutorial/connect-to-your-cluster/#connect-to-your-atlas-cluster).
   Select "Connect your application", set the driver to "Node.js" and the version to "2.2.12 or later".
   This will give a connection string in the form:
   ```
   mongodb://<username>:<password>@<cluster>/<dbname>?ssl=true&replicaSet=<rsname>&authSource=admin&retryWrites=true&w=majority
   ```
   The `<username>` and `<password>` fields need filling in with the details of the database user added earlier. The `<dbname>` field sets the name of the
   database nodegoat will use in the cluster (eg "nodegoat"). The other fields will already be filled in with the correct details for your cluster.

# -----------------------------
# A1 - Inyecci??n

## Las fallas de inyecci??n ocurren cuando se env??an datos que no son de confianza a un int??rprete como parte de un comando o consulta.Los datos hostiles del atacante pueden enga??ar al int??rprete para que ejecute comandos no deseados o acceda a los datos sin la debida autorizaci??n.

#### C??digos vulnerables
eval(), setTimeout(), setInterval(), Function()

#### Tipos de inyeccion 

Inyecci??n sql

Inyecci??n en c??digo

Comandos de sistema operativo

Inyecci??n Ldap

Inyecci??n por xml

Inyecci??n por xpath

Inyecci??n por ssi

Inyecci??n por smtp

buffer overflow

#### EJ: Inyeccion SQL

Un ataque DoS alternativo ser??a simplemente salir o matar el proceso en ejecuci??n:



#### Respuesta
Interrupci??n del servicio

## Remediaci??n
El eval procesa todo incluyendo codigo Java script la remediaci??n mas sencilla fue comentar el codigo y parciar el valor a tipo entero ???parseInt???



# Autenticaci??n y gesti??n de sesiones A2-Broken
## En este ataque, un atacante (que puede ser un atacante externo an??nimo, un usuario con cuenta propia que puede intentar robar datos de las cuentas o un interno que quiere disfrazar sus acciones) utiliza filtraciones o fallas en las funciones de autenticaci??n o administraci??n de sesiones. hacerse pasar por otros usuarios. Las funciones de la aplicaci??n relacionadas con la autenticaci??n y la gesti??n de sesiones a menudo no se implementan correctamente, lo que permite a los atacantes comprometer contrase??as, claves o tokens de sesi??n, o aprovechar otras fallas de implementaci??n para asumir las identidades de otros usuarios.
Los desarrolladores con frecuencia crean esquemas personalizados de autenticaci??n y administraci??n de sesiones, pero construirlos correctamente es dif??cil. Como resultado, estos esquemas personalizados frecuentemente tienen fallas en ??reas como cierre de sesi??n, administraci??n de contrase??as, tiempos de espera, recordarme, pregunta secreta, actualizaci??n de cuenta, etc. Encontrar tales fallas a veces puede ser dif??cil, ya que cada implementaci??n es ??nica.
 
#### Tipos de ataques:

###### Escenario n. ?? 1: los tiempos de espera de las aplicaciones no est??n configurados correctamente. El usuario usa una computadora p??blica para acceder al sitio. En lugar de seleccionar "cerrar sesi??n", el usuario simplemente cierra la pesta??a del navegador y se marcha. El atacante usa el mismo navegador una hora m??s tarde y ese navegador todav??a est?? autenticado.
###### Escenario n. ?? 2: el atacante act??a como intermediario y adquiere la identificaci??n de sesi??n del usuario del tr??fico de red. Luego, usa esta identificaci??n de sesi??n autenticada para conectarse a la aplicaci??n sin necesidad de ingresar el nombre de usuario y la contrase??a.
###### Escenario n. ?? 3: Un intruso o un atacante externo obtiene acceso a la base de datos de contrase??as del sistema. Las contrase??as de los usuarios no est??n correctamente codificadas, lo que expone la contrase??a de todos los usuarios al atacante.

## Protecci??n de las credenciales de usuario


### Los problemas de seguridad relacionados con la administraci??n de sesiones se pueden prevenir tomando estas medidas:
Las credenciales de autenticaci??n de usuario deben protegerse cuando se almacenan mediante hash o cifrado.
 
### Para protegerlo, maneje el almacenamiento de contrase??as de una manera m??s segura mediante el uso de cifrado unidireccional con hash de sal como se muestra a continuaci??n:

        // Create user document
        var user = {
            userName: userName,
            firstName: firstName,
            lastName: lastName,
            benefitStartDate: this.getRandomFutureDate(),
            password: bcrypt.hashSync(password, bcrypt.genSaltSync())
### Hay aplicaciones como rainbow table stack que busca en diferentes bases de datos puplicas distintos hash (mas habituales) y por medio de un metodo de comparacion se puede saber cual es la password sin hashear.El metodo Salt permite incroporarle un randon mas al hash y asi obtener una barrer contra este tipo de aplicaciones.


        function comparePassword(fromDB, fromUser) {
                    return bcrypt.compareSync(fromDB, fromUser);


### El metodo bcrypt va a comparar el hash obtenido por el strig que le envio el usuario con el hash almacenado en la base de datos . Esto obtendra un true/false que le permitira/denegara el acceso. 
 (user-dao.js)
## Proteger cookies en tr??nsito

            cookie: {
            httpOnly: true,
             secure: true
        }
        
### En este cado si seteamos httpOnly en true la cokie solo puede ser accedida por http y no por scripting 
Secure true la cookie es enviada al dominio que corresponde pero solo en https
(server.js)

### Otra manera de proteger las cookies en tr??nsito es destruirlas al momento de cerrar sesi??n
 
    this.displayLogoutPage = function(req, res, next) {
        req.session.destroy(function() {
            res.redirect("/");
        });
    };

(session.js)
## Adivinar contrase??as

### En varios casos el mensaje de aplicacion puede ser una pista para un atacante en el caso de NodeGoat al poner mal un dato el mensaje es ???Usuario invalido??? de esta manera le estamos diciendo al atancante que el dato que esta mal es el de usuario 
Mensaje correcto

        userDAO.validateLogin(userName, password, function(err, user) {
            var errorMessage = "Acceso inv??lido. Por favor, int??ntelo otra vez.";
(session.js)

### Se debe exigir mejor calidad para evitar contrase??as deviles

var PASS_RE =/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/;

        if (!PASS_RE.test(password)) {
            errors.passwordError = "La contrase??a debe tener entre 8 y 18 caracteres" +
                "incluyendo n??meros, letras min??sculas y may??sculas..";
(session.js)



 

# Secuencias de comandos A3 entre sitios (XSS)
## Los defectos de XSS ocurren cuando una aplicaci??n toma datos que no son de confianza y los env??a a un navegador web sin la validaci??n o el escape adecuados. XSS permite a los atacantes ejecutar scripts en el navegador de las v??ctimas, que pueden acceder a las cookies, tokens de sesi??n u otra informaci??n confidencial retenida por el navegador, o redirigir al usuario a sitios maliciosos.

## En nodegoat vemos un xss de tipo almacenad. Lo que hace es enviar un xss al servidor se puede ver una salida como si fuesa reflected (el servidor repite los datos maliciosos en una respuesta inmediata a una solicitud HTTP de la v??ctima) pero adem??s se guarda en alg??n lado sin sanitizar (el c??digo aun permanece). Lo prevenimos sanitizando este tipo de entrada que env??an JavaScripting como la salida. El XSS es aun mas peligroso si nuestra cookie de sesion no utiliza el http Only (Es dif??cil prevenir todos los defectos XSS en una aplicaci??n. Para ayudar a mitigar el impacto de una falla XSS en su sitio, configure la marca HTTPOnly en la cookie de sesi??n y cualquier cookie personalizada a la que no se requiera acceder mediante JavaScript.) esto hace que la cookie de sesi??n sea ??nicamente utilizado por HTTP. Otra protecci??n es Implementar la pol??tica de seguridad de contenido (CSP) b??sicamente esto hace que le definamos a quienes acceden a los script (podemos poner que accedan los del mismo dominio que la pagina o los de una lista blanca)

## El nodegoat utiliza unas paginas que se llaman swing. Poniendo el autoscape un true hace que si usamos las paginas din??micas como la que hay que usar nos va a escapear el XSS


swig.init ({
    root: __dirname + "/ app / views",
    autoescape: true // valor predeterminado
});
 
autoescape : true
(server.js,) 
# Referencias de objetos directos inseguras de A4
## Una referencia directa a un objeto ocurre cuando un desarrollador expone una referencia a un objeto de implementaci??n interno, como un archivo, directorio o clave de base de datos. Sin una verificaci??n de control de acceso u otra protecci??n, los atacantes pueden manipular estas referencias para acceder a datos no autorizados.
En el caso de NodeGoat al hacer una consulta sobre alocation en la url podemos ver el parametro de sessionID, simplemnte cambiando el numero de sessionID podemos ver informacion de otro usuario 
imagen
la correccion 
   
this.displayAllocations = function(req, res, next) {
        
// Fix for A4 Insecure DOR -  take user id from session instead of from URL param
        
var userId = req.session.userId;
        
 //var userId = req.params.userId;




# Configuraci??n incorrecta de A5-Security
## Esta vulnerabilidad permite que un atacante acceda a cuentas predeterminadas, p??ginas no utilizadas, fallas sin parches, archivos y directorios desprotegidos, etc. para obtener acceso no autorizado o conocimiento del sistema.
## La configuraci??n incorrecta de la seguridad puede ocurrir en cualquier nivel de una pila de aplicaciones, incluida la plataforma, el servidor web, el servidor de aplicaciones, la base de datos, el marco y el c??digo personalizado.
## Los desarrolladores y los administradores del sistema deben trabajar juntos para garantizar que toda la pila est?? configurada correctamente.
### Un ejemplo de esta vulnerabilidad en el NodeGoat es realizar F5 en la p??gina home Encontramos datos que son interesantes para un atacante Nos muestra el banner del servidor web Ese banner en particular dice powered-bi 
Introducir foto C12 Min05:01

###### Los que no est?? diciendo con esto es el framework del lado backend Es el framework Express de node.js
###### Esto es vulnerabilidad porque da mas informacion de la que deber??amos dar. Un atacante puede buscar vulnerabilidades con la versi??n del framekork. Su ataque queda mejor enfocado.
En este caso debemos usar una cookie de sesi??n con un nombre mas gen??rico

### Otro caso en particular es que no se est??n usando los headers de seguridad. 
Se puede utilizar el framework helmet. Trae protecciones para usar head seguros protegiendo al usuario final. 

npm install helmet --save
"helmet": "^0.9.1",
(package.json)

    // Eliminar el encabezado de respuesta
    app.disable("x-powered-by");

    // Evite la apertura de la p??gina ( secuestro de clics)
    app.use(helmet.xframe());
   
    // almacena en cache y pagina
    app.use(helmet.noCache());

    // Permito cargar recursos solo de lista blanca
    app.use(helmet.csp);

    // solo comunicaci??n HTTPS
    app.use(helmet.hsts());

//Obliga al navegador a usar solo el tipo de contenido establecido en el encabezado de respuesta
   app.use(nosniff());

//uso gen??rico de cookie
key: "sessionId",








(server.js)



# Exposici??n de datos sensibles - A6
## Esta vulnerabilidad permite que un atacante acceda a datos confidenciales como tarjetas de cr??dito, identificaciones fiscales, credenciales de autenticaci??n, etc. para realizar fraudes con tarjetas de cr??dito, robo de identidad u otros delitos. La p??rdida de estos datos puede causar un impacto comercial severo y da??ar la reputaci??n. Los datos confidenciales merecen una protecci??n adicional, como el cifrado en reposo o en tr??nsito, as?? como precauciones especiales cuando se intercambian con el navegador.

// carga para establecer una conexi??n HTTPS segura
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
## Encriptaci??n de datos del usuario
    // librer??a cripto para guardar datos confidenciales cifrados
    var crypto = require("crypto");
    var config = require("../../config/config");
    // funci??n para cifrar datos
    var encrypt = function(toEncrypt) {
        var cipher = crypto.createCipher(config.cryptoAlgo, config.cryptoKey);
        return cipher.update(toEncrypt, "utf8", "hex") + cipher.final("hex");
    };
    // funci??n para descifrar datos
    var decrypt = function(toDecrypt) {
        var decipher = crypto.createDecipher(config.cryptoAlgo, config.cryptoKey);
        return decipher.update(toDecrypt, "hex", "utf8") + decipher.final("utf8");
    };
(profile-dao.js)
# A7-Control de acceso de nivel de funci??n faltante
## La mayor??a de las aplicaciones web verifican los derechos de acceso a nivel de funci??n antes de hacer visible esa funcionalidad en la interfaz de usuario. Sin embargo, las aplicaciones deben realizar las mismas comprobaciones de control de acceso en el servidor cuando se accede a cada funci??n.

###### Dentro de NodeGoat viene seteado 
app.get("/benefits", isLoggedIn, benefitsHandler.displayBenefits);
app.post("/benefits", isLoggedIn, benefitsHandler.updateBenefits);

###### Esto hace que no se verifique si el usuario que accede a la pagina de beneficios es admin

## corregimos
     app.get("/benefits", isLoggedIn, isAdmin, benefitsHandler.displayBenefits);
     app.post("/benefits", isLoggedIn, isAdmin, benefitsHandler.updateBenefits);
     
## y comprobar si el usuario tiene derechos de administrador

var SessionHandler = require ("./ sesi??n");
var isAdmin = sessionHandler.isAdminUserMiddleware;



### En esta imagen vemos que al usuario por m??s que modifique la url no le trae informaci??n.
# A8-Falsificaci??n de solicitud entre sitios (CSRF)
## Un ataque CSRF obliga al navegador de una v??ctima que ha iniciado sesi??n a enviar una solicitud HTTP falsificada, incluida la cookie de sesi??n de la v??ctima y cualquier otra informaci??n de autenticaci??n incluida autom??ticamente, a una aplicaci??n web vulnerable. Esto permite al atacante obligar al navegador de la v??ctima a generar solicitudes que la aplicaci??n vulnerable procesa como solicitudes leg??timas de la v??ctima.

## Es un ataque donde el navegador de la victima es enga??ado para que emita un comando a una aplicaci??n web vulnerable ??? La vulnerabilidad es causada debido a que los navegadores incluyen autom??ticamente informaci??n de autenticaci??n del usuario (ID de sesi??n, direcci??n IP, credenciales de dominio Windows, ...) en cada pedido HTTP
 
## Esta vulnerabilidad esta descontinuada y existe una librer??a que evita estos ataques. (la mayor??a de los framework ya tienen protecci??n contra esta vulnerabilidad)
    
    // Habilita la protecci??n Express csrf
    app.use(csrf());
@@ -120,7 +120,7 @@ MongoClient.connect(config.db, function(err, db) {
        res.locals.csrftoken = req.csrfToken();
        next();
    });

(server.js)


# A9-Uso de componentes con vulnerabilidades conocidas
## B??sicamente este tipo de herramientas en el caso de node.js es validar las dependencias en un Json y cada dependencia tiene sus propias dependencias. Por el ejemplo swing publifile que tiene una vulnerabilidad publicada. 
Lo que debemos hacer es mirar las versiones encontradas en el Jason y corregirlas. Luego volver a generar el proyecto. De esta manera se corrigen las dependencias que tenemos actualmente 
Estas correcciones se pueden resolver con npm Audit 
Prevenimos esta vulnervilidad 
No ejecute aplicaciones con privilegios de root
Prefiera paquetes que incluyan an??lisis de c??digo est??tico. Verifique JSHint / JSLint la configuraci??n para saber qu?? reglas cumple el c??digo
Prefiera paquetes que contengan pruebas unitarias completas y pruebas de revisi??n para las funciones que utiliza nuestra aplicaci??n
Revise el c??digo en busca de cualquier archivo inesperado o acceso a la base de datos
Investiga qu?? tan popular es el paquete, qu?? otros paquetes lo usan, si el autor ha escrito otros paquetes, etc.
Bloquear la versi??n de los paquetes utilizados
Mire los repositorios de Github para ver las notificaciones. Esto nos informar?? si se descubre alguna vulnerabilidad en el paquete en el futuro.
# A10: redireccionamientos y reenv??os no validados
## Las aplicaciones web suelen redirigir y reenviar a los usuarios a otras p??ginas y sitios web, y utilizan datos que no son de confianza para determinar las p??ginas de destino. Sin la validaci??n adecuada, los atacantes pueden redirigir a las v??ctimas a sitios de phishing o malware, o utilizar reenv??os para acceder a p??ginas no autorizadas.

### En el caso de NodeGoat cuando nos posicionamos sobre una secci??n de la p??gina, nos muestra en la parte inferior el link (la muestra a trav??s de un par??metro) donde nos vamos a redirigir.
Estos links nos pueden llevar a un lugar malicioso (malware, pishing) y la remediaci??n es harcodeando la url. 

    app.get("/learn", isLoggedIn, function(req, res, next) {
    /*app.get("/learn", isLoggedIn, function(req, res, next) {
        // Insecure way to handle redirects by taking redirect url from query string
        return res.redirect(req.query.url);
    });
    });*/

<li><a id="learn-menu-link" target="_blank" href="https://www.khanacademy.org/economics-finance-domain/core-finance/investment-vehicles-tutorial/ira-401ks/v/traditional-iras"><i class="fa fa-edit"></i> Learning Resources</a>                    </li>                    {% endif %}                    <li><a id="logout-menu-link" href="/logout"><i class="fa fa-power-off"></i> Logout</a>

(index.js) 




	





