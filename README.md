# **MCS Micro-Vault**

Micro-Vault microservice dead simple key management service without any golden rings, just simple and secure.
The following documentation is written in German.

## Wofür gibt es diesen Service?

Die Idee zu diesen Service entstand bei einem privaten Mikroservice Projekt. Dabei gab es 2 grundlegende Probleme in der Implementierung. 

### Zertifikate, Zertifikatsstelle, Certificate authority

Beispiel: Innerhalb eines Kubernetes Clusters kommunizieren  die Services untereinander über REST. Alle Services verwenden HTTPS mit selbst signierten Zertifikaten. Das macht bei der Anbindung an Fremdsysteme jedoch Probleme. Diese verlangen in den meisten Fällen ordnungsgemäß signierte Zertifikate. Es gibt dazu verschiedene Lösungsansätze. Natürlich kann man generell im Container ein öffentliches Zertifikat hinterlegen. So können ext. Services nun auf diesen Container zugreifen. Leider kann man die DNS Aliase nicht selber bestimmen. D.h. bei jeder Änderung z.B. des Service-Namens im Namespace muss ein neues Zertifikat erstellt werden. Das ist einfach aufwendig. Zum Automatisieren kommen mehrere Wege in Betracht. 

- Erzeugung des Zertifikates beim Hochfahren des Containers. Leider verzögert dieser Schritt den Start des Containers doch erheblich, so dass eine automatische Skalierung beim Loadbalancing dabei nachteilig beeinflusst wird. Nebenbei haben dann alle Instanzen eines Service unterschiedliche Zertifikate, was evtl. auf der Clientseite zu Problemen führen kann. Bei Änderungen der DNS, IP muss dann der Service neu gestartet werden. 
- Erzeugung zur Buildzeit, somit haben alle Nodes das gleiche Zertifikat, zur Erneuerung muss dann aber ein neuer Build (mit evtl. Nebenwirkungen) gemacht werden. Bei Änderungen der DNS, IP muss dann der Build neu gestartet werden. 
- Erzeugung offline und kopieren aus einem ext. Speicher (build oder Startzeit), diese Variante könnte sicherheitstechnisch problematisch sein, denn der Zertifikatsspeicher muss gut abgesichert werden. 

Abhilfe schafft da eine zentrale Zertifikatsstelle im Cluster (Certificate authority, CA), die direkt den CSR ausführen kann. Somit müssen die Clients zur Zertifikatskontrolle nur das Root Zertifikat der CA importiert haben.

### Verschlüsselte Übertragung

Bestimmte Daten sollen zwischen Services über einen dritten öffentlichen Service (Message Broker) sicher ausgetauscht werden können. d.h. die Daten sollten für andere nicht beteiligte Komponenten nicht einsehbar sein. Auch nicht für einen Administrator. Es besteht aber zwischen den kommunizierenden Services keine direkte Verbindung. (Beide Service können sowohl zeitlich wie auch Räumlich getrennt sein.) 

Hier mal ein Beispiel einer Messaging Kommunikation zwischen 2 Services über eine dritte nicht vertraute Umgebung.

Auch wenn die eigentliche Kommunikation zwischen den einzelnen Services verschlüsselt stattfindet, kann ein Angreifer an die Daten gelangen. Denn wie die Datenablage erfolgt, ist nicht immer ersichtlich und auf dem Messingsystem liegen zumindest zeitweise die Daten in unverschlüsselter Form vor. 

![scenario_1](./doc/images/scenario_1.svg)



Man kann natürlich die Daten bereits auf der Sendeseite von MS1 verschlüsseln und dann auf der Empfangsseite von MS2 wieder entschlüsseln.

![scenario_2](./doc/images/scenario_2.svg)

Aber wie kommt der Schlüssel von A nach B? 

Eine durchaus verbreitete Variante (ähnlich TLS) ist, den symmetrischen Schlüssel in der Payload zu schicken. Dieser wird dann mit dem öffentlichen Schlüssel des Zertifikates von Microservice 2 verschlüsselt. (Asymmetrische Verschlüsselung) Microservice 2 kann dann zunächst mit seinem privaten Schlüssel den symmetrischen Schlüssel dekodieren und dann die eigentliche Payload entschlüsseln.  

Soweit funktioniert das auch recht gut. Nachteil ist allerdings, Microservice 1 muss irgendwie an den öffentlichen Schlüssel von Microservice 2 kommen. Um nicht eine direkte Abhängigkeit von MS1 zu MS2 zuhaben, kann man das konfigurativ erledigen oder man legt die Schlüssel in einen zentralen Schlüsselspeicher. D.h. Es gibt einen dritten Vertrauten, hier Vault, der als Vermittler dient.

![scenario_3](./doc/images/scenario_3.svg)

Der Client 1 muss nun aber weiterhin neue symmetrische Schlüssel generieren, MS2 muss einen asymmetrischen Schlüssel verwalten. In einer Multinode-Umgebung ist die Verwaltung dabei eine Herausforderung. Nicht nur, dass auf der MS2 Seite nun die privaten Schlüssel an alle Nodes verteilt werden müssen. Auch beim Wiederruf eines kompromittierten Zertifikates müssen die neuen Zertifikate an alle Nodes und Vault ausgerollt werden. Und auch die Schlüsselgenerierung auf der Client 1 Seite birgt Risiken. Besser wäre es wenn auch der private Schlüssel von MS 2 mit in dem Vault gelegt würde und nur bei Bedarf über eine sichere Verbindung übertragen wird. Der nächste logische Schritt ist es dann, auch die symmetrischen Schlüssel im Vault zu speichern und nur eine ID zur Identifizierung des Schlüssels an den Client 2 weiter zu geben. Vault kann dann durch zusätzliche Attribut checken, ob ein Zugriff auf den Schlüssel erlaubt ist. Somit entfällt auch die Notwendigkeit den symmetrischen Schlüssel mit dem öffentlichen Schlüssel von Client 2 zu verschlüsseln. Zusätzlich kann nun die Nachricht auch weiteren Clients zur Verfügung gestellt werden, den Zugriff auf die Schlüssel regelt dann Vault anhand von Zugriffsregeln. 

![scenario_4](./doc/images/scenario_4.svg)



Da Vault nun alle Informationen zur Kommunikation hat, kann man der Ver/Entschlüsseln bzw. das Signieren und den Check dazu auch komplett auf Vault verlegen. Die Clients verwalten dann nur noch eine Verbindung. Nachteil ist dann natürlich, dass Vault neben der Schlüssel- und Clientverwaltung, nun auch die deutlich Resourcen-bindende Arbeit des Ver/Entschlüsselns bzw. der Signierung übernehmen muss. In sofern ist die Nutzung von Serverside Encryption auch nur bei kleiner Payload zu empfehlen. 

### Was bietet nun Micro-Vault?

Micro-Vault bietet genau das, nicht mehr aber auch nicht weniger. 

Service-Client sind per Namen identifizierbar. 

Micro-Vault ermöglicht die Erstellung signierter Zertifikate für die Clients und dient als CA (Certificate Authority). Jeder Service-Client kann signierte Zertifikate anfordern. Andere Clients, die dann diese Zertifikate validieren, benötigen nur das Root Zertifikat von der Micro-Vault-Instanz. Die Zertifikate können im MV UI mit bestimmten Eigenschaften, wie DNS Namen, IP Namen... konfiguriert werden. Vorteil es gibt eine zentrale Stelle, wo alle Zertifikatsinformation der verschiedenen Services konfiguriert werden können. Je nach Service Implementierung muss man dann nur noch dafür sorgen, dass die Services die neuen Zertifikate abholen.
Um den von Micro-Vault ausgestellten Zertifikaten zu vertrauen, reicht es aus das Stammzertifikat von Micro-Vault zu installieren. Dieses kann über die mvcli auch automatisiert erfolgen. (`mvcli cacert`) 

Die Client-Anmeldung erfolgt dann per AccessKey und Secret. Das Secret wird nur bei dem Client-Anlegerequest einmalig ausgegeben. Die eigentlichen Funktionen können dann über das bei der Anmeldung ausgestellte Token angesprochen werden. Ist dieses Token abgelaufen, kann entweder per RefreshToken einmalig oder per AccessKey/Secret ein neues Token ausgestellt werden. Clients können Gruppen zugeordnet werden. Nur innerhalb einer Gruppe können Keys (Signatur) und Schlüssel (Crypt) ausgetauscht werden. Jeder Client ist automatisch in seiner eigenen Gruppe, d.h. jeder Client kann sich auch "private" Keys ausstellen lassen. 

Zur Anbindung an Micro-Vault werden 2 REST Interfaces angeboten, einmal der Admin Bereich für das Management der Gruppen und Clients und ein weiteres REST Interface für den Client Bereich. 

Der Adminbereich ist per BasicAuth (Username/Passwort) bzw. per JWT und externem Identity-Management ansprechbar. Hier werden Gruppen und Clients verwaltet. Auch der Adminzugangs arbeitet mit einem Token/RequestToken Verfahren. 

## Persistierung/Speichermodelle

Die Speicherung kann auf mehrere Arten erfolgen. Implementiert sind derzeit 3 Storagearten

1. In Memory: Hier werden alle relevanten Daten im Speicher des Microservice gehalten. Kein Multinodebetrieb.
2. Filesystem: Mit diesem Storage werden die Daten in einer filebasierten Datenbank (BadgerDB) gehalten. Kein Multinodebetrieb.
3. MongoDB: Hier werden alle Daten verschlüsselt in einer MongoDB abgelegt. Multinodebetrieb möglich.

### InMemory

Im Memory-only Modell werden alle Daten ausschließlich im Speicher gehalten. Wird der Service neu gestartet, werden alle Einstellungen neu generiert. Es findet keine dauerhafte Persistierung statt. Für die Initialisierung beim Start kann ein Playbook verwendet werden. Somit können Clients, Gruppen und Keys direkt beim Start erstellt werden. Ein echter Multinodebetrieb ist mit diesem Storage aber nicht möglich, da neu angelegte Keys (wie auch Clients und Groups) zwischen den verschiedenen Knoten nicht ausgetauscht werden. Werden keine neuen Schlüssel erzeugt, kann bei gleichem Playbook eine einfache Lastverteilung erfolgen. ACHTUNG: Bei dieser Art sind Änderungen weder persistent noch können diese auf andere Nodes übertragen werden.  

### Filesystem

Alle Daten werden auf dem Filesystem gespeichert. Ein Playbook kann auch hier zur Initialisierung verwendet werden. Bereits gespeicherte Objekte haben allerdings Vorrang. Als Speicher wird eine BadgerDB verwendet. Ein Multinodebetrieb ist mit diesem Storage nicht möglich.

### MongoDB

Alle Daten werden verschlüsselt in einer MongoDB abgelegt. Die Datenbank wie auch die Collection und der Index müssen von Hand angelegt werden. Für eine Development Instanz gibt es im Doc Ordner die Datei  dev.md mit den entsprechenden Befehlen für die Mongo Shell. Dieser Storage kann auch im Multinode Betrieb verwendet werden, wenn alle Nodes auf die gleiche MongoDB Zugriff haben und das gleiche private Zertifikat verwendet wird. Hier werden alle Informationen ausgetauscht.

### Multinodebetrieb

Voraussetzung für den Multinodebetrieb ist die Verwendung einer Datenbank als Speicher. Da die Daten in der Datenbank verschlüsselt abgelegt werden, muss jeder Service-Node mit dem gleichen Zertifikat ausgestattet werden. Eine externe Zertifikatsrotation ist mit Hilfe des MV-Migrationstool möglich.

## Kommunikationsablauf

### Usecase 1: Client A möchte an alle Clients der Gruppe B eine verschlüsselte Nachricht schicken.

- Client A meldet sich mit AccessKey und Secret an -> MV gibt ein JWToken zurück
- Client fordert ein Gruppen-Verschlüssellungszertifikat an -> MV generiert für die Gruppe B einen AES Schlüssel und eine ID. Beides wird als Antwort zu Client A gesendet.
- Client verschlüsselt die Nachricht, fügt der Nachricht die ID hinzu und versendet das ganze.
- Client C der Gruppe B ruft die Nachricht ab.
- Client C meldet sich an MV an, -> erhält ein JWT
- Client C fordert den Schlüssel mit der ID an, -> MV sucht in allen Gruppen von Client C nach dem Schlüssel zu ID, liefert diesen dann zurück
- Client C entschlüsselt die Nachricht. 

### Usecase 2: Client A möchte an Client B eine verschlüsselte Nachricht schicken

- Client A meldet sich mit AccessKey und Secret an -> MV gibt ein JWToken zurück
- Client fordert den Public Key von Client B an -> MV prüft ob A und B gemeinsame Gruppen haben. Public Key B wird als Antwort zu Client A gesendet.
- Client verschlüsselt die Nachricht und versendet das ganze.
- Client B ruft die Nachricht ab.
- Client B ruft seinen persönlichen Schlüssel ab.
- Client B entschlüsselt die Nachricht mit persönlichem Schlüssel. 

### Usecase 3: Client A möchte Daten einer Nachricht mit einer Signatur versehen

- Client A meldet sich mit AccessKey und Secret an -> MV gibt ein JWToken zurück
- Client A ruft seinen persönlichen Schlüssel ab.
- Client A bildet mit seinem privaten Schlüssel über die Daten eine Signatur
- Client A versendet die Nachricht, die Signatur und seinen Namen.
- Client B ruft die Nachricht, Signatur und den Namen ab.
- Client B fordert den öffentlichen Schlüssel von Client A an -> MV prüft die gemeinsamen Gruppen 
- Client B prüft die Signatur. 

### Serverside Encryption/Signing

Zusätzlich zu der im Client (Goclient) implementierten Verschlüsselung und Signierung implementiert MV auch einen Serverseitigen Ansatz. D.h. jeder Client kann Daten über den Server ver-/entschlüsseln bzw. signieren/validieren. Somit werden lokal keine Crypto Bibliotheken benötigt.

## Playbook

Das Playbook kann per Config (Einstellung playbook file) oder per Commandline (--playbook -b) übergeben werden. Eine Übergabe ist auch einmalig nach dem Start per REST POST möglich. Bei Ausführung mehrere Optionen wird folgende Reihenfolge verwendet. Bei gleichen Einstellungen erfolgt ein Merge. 

**Reihenfolge:** Config -> Commandline -> REST

playbook.json

```json
{
    "groups": [{
            "name": "group1",
            "label": {
                "de": "Gruppe 1",
                "en": "Group 1"
            }
        }, {
            "name": "group3",
            "label": {
                "de": "Gruppe 3",
                "en": "Group 3"
            }
        }, {
            "name": "group4",
            "label": {
                "de": "Gruppe 4",
                "en": "Group 4"
            }
        }
    ],
    "clients": [{
            "name": "tester1",
            "accesskey": "12345678",
            "secret": "e7d767cd1432145820669be6a60a912e",
            "groups": ["group1", "group4"],
            "key": "{PEM file content} -----BEGIN PRIVATE KEY-----  \nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKc...\n-----END PRIVATE KEY-----",
            "kid": "h_oL_duFx67WHB9fd5-VKXnCHNvHj33ZDIokD_dEhyQ"
        }, {
            "name": "tester2",
            "accesskey": "87654321",
            "secret": "e7d767cd1432145820669be6a60a912e",
            "groups": ["group2", "group4"],
            "key": "{PEM file content} -----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwgg...\n-----END PRIVATE KEY-----",
            "kid": "M5pQtcH5y2zxBtdhs-eAS7iJWiQzFsrsYMorkCMRi3s",
            "crt" : {
              "dns" : ["Micro-Vault.local", "search.local"],
              "ip": ["192.168.178.10"],
              "ucn": "search",
              "vad": "30d"
            }
        }
    ],
    "keys": [{
            "ID": "cgi3qlg11fjkco1661j0",
            "Alg": "AES-256",
            "Key": "ab6e010b7889d9547e0005459342a04a292e0866df11caf27bba3e108f7ff178",
            "Created": "2023-03-29T15:29:58.2497919+02:00",
            "Group": "group1"
        }, {
            "ID": "cghve2g11fjp746madig",
            "Alg": "AES-256",
            "Key": "efe722017f1798051d96f6e7d888ae6614cf111b5e43ad57180c9ba74b833a6c",
            "Created": "2023-03-29T10:30:02.5429664+02:00",
            "Group": "group1"
        }
    ]
}
   
```

Aus Sicherheitsgründen gibt keinen Weg, ein Playbook aus einem laufenden Server zu exportieren.  Allerdings gibt es einen Commandozeilen Parameter mit dem das Binary eine playbook.json aus einer Installation erzeugt. Dazu muss das Binary mit den gleichen Einstellungen wie der Service gestartet werden. 

# Clients 

## Command Client

Für eine einfache Benutzung gibt es neben dem Golang Client auch einen Kommandozeilenclient. Dieser deckt die wichtigsten Funktion sowohl im Admin Bereich wie auch im Client Bereich ab. 

Hier die aktuellen Hilfe:

```sh
C:\>mvcli.exe --help
micro-vault microservice dead simple key management service without any golden rings, just simple and secure.

Usage:
  mvcli [command]

Available Commands:
  cacert      Getting the root certificate of the ca
  completion  Generate the autocompletion script for the specified shell
  create      Create an object in your Micro-Vault instance
  get         Get an object from your Micro-Vault instance
  help        Help about any command
  list        List different objects
  login       Login into a Micro-Vault service
  logout      Logout from a Micro-Vault service
  playbook    Upload and execute a playbook
  update      Updating parameters of an already created object

Flags:
  -h, --help   help for mvcli

Use "mvcli [command] --help" for more information about a command.
```

Ich hoffe das das UI selbsterklärend ist. 

### Login

```
C:\>mvcli.exe login --help
With login you start an mvcli session. 
Please enter the URL for the service,
as well as the root user name and password.

Usage:
  mvcli login [flags]

Flags:
  -a, --accesskey string   insert the client acceskey
  -h, --help               help for login
  -p, --password string    insert the password of the admin account
  -s, --secret string      insert the secret of the client
      --url string         insert the url to the mv service (default "https://localhost:8443")
  -u, --username string    insert the admin account name (default "root")
```

Mit dem Login Kommando startet man eine MV Session. Je nach Parameter wird entweder einen Client oder Admin Session gestartet. Bei der Anmeldung wird vom Server ein Token ausgestellt und ins Benutzerverzeichnis gespeichert (`mv_client.json`). Dieses wird für die weiteren Kommandos verwendet. Dieses Token ist 15 min gültig. Wird danach ein weiterer Zugriff versucht, wird zunächst mit dem RefreshToken (60min) eine erneute Anmeldung versucht. Ist auch dieses abgelaufen, muss eine erneute Anmeldung erfolgen. Je nach Parameter unterscheidet der Client selber, welcher Anmeldetyp versucht wird. Mit dem Tupel Username, Passwort (-u und -p) wird eine Anmeldung als Admin versucht. Bei Accesskey und Secret (-a und -s) wird eine Clientanmeldung versucht. Natürlich funktionieren nicht mit jedem Anmeldetyp alle Kommandos. Für bestimmte Kommandos muss eine Admin Anmeldung erfolgen. Bei der Anmeldung muss natürlich auch die BasisURL zu dem MV Service angegeben werden. Beispiele

Adminanmeldung

```
C:\>mvcli.exe login -u root -p yxcvb --url https://127.0.0.1:9543
login successful, expires: 2023-05-02 11:30:39 +0200 CEST 
```

Clientanmeldung

```
C:\>mvcli.exe login -a 12345678 -s e7d767cd1432145820669be6a60a912e --url https://127.0.0.1:9543
login successful, expires: 2023-05-02 11:18:24 +0200 CEST 
```

Folgende Kommandos funktionieren ohne Anmeldung.

```
C:\>mvcli.exe cacert --url https://127.0.0.1:9543
Getting the root certificate of the Micro-Vault certificate authority

Usage:
  mvcli cacert [flags]

Flags:
  -h, --help         help for cacert
      --url string   insert the url to the mv service (default "https://localhost:8443")
```

## Golang Client

Für Golang gibt es eine eigene Client-Bibliothek. 

Beispiele zur Anwendung kann man unter example/golang finden.

# REST Endpunkte

## öffentlicher  Schlüssel

Zum Validieren der Tokens steht der öffentliche Schlüssel (JWKS konform) unter `/.well-known/jwks.json` zur Verfügung. Als Antwort bekommt man die folgende Struktur:

```json
{
    "keys": [
        {
            "alg": "RS256",
            "e": "AQAB",
            "kid": "7sBXW-qQqZbjjCtnT5h4YqZwDiJtA73oYeErP7k59SM",
            "kty": "RSA",
            "n": "qJdyURUnM9N1UYk1RViSYFgSi41cO7K-G3Grdp4kk1PxDR-H2MIn9HkdKpqy5ul_0RHIe9D-s66Oy2LJl50Wjh3fBW6psZuQKWOqzisgUB60ChieW9fryyXzfXagBWpEDvW9j6hundG7pR2w8-SgARwyDgs10Egal9Oi-3zHG-T6ie_Uc-QZh4r8n3q2HR7c-afdt9zlGmx38jto4hXIcpvRol9rH5qafoZ730TVX1q48I3IKOMtwFcoIXQXBzR3D-fLt8Pu9DCbOsbuP8u-6ynExHwy9x-rjqyMa1ZjxAQhwqOpnhNHvTlzNY3v8wdO5enHi0JzIwhmNdzlJEoKiQ",
            "use": "sig"
        }
    ]
}
```

## Stamm-Zertifikat der MV CA

Das Stammzertifikat der MV CA steht öffentlich unter /ca/cacert zur Verfügung. (Auch der interne Webserver verwendet ein eigenes Zertifikat, welchen von der internen CA signiert wurde.)

### Linux

Um dieses herrunter zu laden ruft man einfach 

`curl -k https://<serverurl>/ca/cacert >cert.crt`

Danach muss unter Linux das Zertifikat unter /usr/local/share/ca-certificates/ gespeichert werden.

`mv cert.crt /usr/local/share/ca-certificates/mv-cert.crt`

Nun muss noch einmal `update-ca-certificates` aufgerufen werden.

### Windows

Wie man das Stammzertifikat unter Windows installiert, kann auf den entsprechenden Internet Seiten nach gelesen werden. 

## Login

Für die Anmeldung, egal ob admin oder service client gibt es nur 2 Endpunkte. Einmal für den Login und einmal für den Tokenrefresh. Anhand der Parameter entscheidet sich dann, ob ein Admin Login oder ein Client Login ausgeführt wird.

Beim Clientlogin müssen Accesskey (accesskey) und Secret (secret) übergeben werden. Für den Admin Login wird ein Username (user) und ein Passwort (pwd) erwartet. (Das Passwort ist ein mimekodierter String als Byte Array)

Der übliche Kommunikationsablauf (im Basic Auth Betrieb) ist wie folgt:
Die erste Anmeldung erfolgt mit Usernamen/Passwort an dem Login Endpunkt. Daraufhin wird ein Token und ein RefreshToken erzeugt und dem Client übergeben. Mit dem Token, das üblicherweise 5 min gültig ist, können nun die verschiedenen Endpunkte benutzt werden. Ist das Token abgelaufen, kann mit dem RefreshToken an dem Endpunkt Refresh ein neues Token/RefreshToken Pärchen abgerufen werden. Das Refreshtoken ist üblicherweise 60 min gültig und kann nur zum Tokenrefresh verwendet werden. Ist auch das abgelaufen, muss eine erneute Anmeldung erfolgen.

Bei der Erstellung eines CLients wird für diesen Client automatisch ein privater RSA Schlüssel generiert. Dieser kann auch hier abgerufen werden.

### Login

Anmeldung als Admin/Client an MV. 

URL: POST /api/v1/login

In; user/pwd oder accesskey/secret

Out: Token, RefreshToken

### Refresh

Refresh einer Anmeldung an MV. 

URL: GET /api/v1/login/refresh

In; Authorization mit dem Refreshtoken

Out: Token, RefreshToken

### Private Key

privater Schlüssel des Clients als PEM Block. 

URL: GET /api/v1/login/privatekey

In; Authorization mit Client Token

Out: PEM Datei mit dem privaten RSA Schlüssel

## Admin

Im Adminbereich finden sich die Endpunkte zum anlegen eines Clients, Secret-Erneuerung, Gruppen-Administration. Wenn nicht anders vermerkt, sind die Endpunkte nur über einen angemeldeten User mit Adminrechten zu benutzen. Andere sind auch für angemeldete Clients benutzbar. 

### Client CRUD

#### Client erzeugen (Create)

Hiermit wird ein neuer Client erzeugt. 

In: Gruppen

Out: Access-Key, Secret

#### Client Info (READ) *all 

Info über den Client 

Out: Accesskey, Secretablaufdatum, Gruppenzugehörigkeit

#### Client Secreterneuerung (Update)

Hier wird ein für den Client ein neues Secret angefordert. 

In: altes Secret

Out: neues Secret 

#### Client löschen (Delete)

Löscht den Client vom MV Service

#### Client Groups AD

Add, Delete fügt neue Gruppen zu einem Client hinzu, bzw. löscht mehere GRuppen eines Clients

### Gruppen CRUD

Crud Endpunkte für die Gruppen. 

#### Gruppe anlegen (Create), Update(Update) und Löschen (Delete)

Verwaltung der Gruppen

#### Gruppe lesen (Read) *all

die Gruppeninfos aller Gruppen sind für jeden angemeldeten Client lesbar.

### Playbook Post

Mit diesem Endpunkt kann ein Playbook hoch geladen und ausgeführt werden. Dieses gilt dann als Basis für den weiteren Betrieb.  Mit dem Playbook können Clients, Gruppen und Keys erstellt werden.

URL: POST /admin/playbook

In: Playbook Json

Out: No Content

### Utils Certificate

#### Dekodieren eines Zertifikates

Mit diesem Endpunkt kann man ein öffentliches Zertifikat dekodieren und als JSON zurück geben lassen. Achtung: Das Zertifikat wird nur konvertiert und nicht geprüft.

URL POST /admin//utils/decodecert

In: Zertifikat im PEM Format

Out: Dekodiertes Zertifikat in JSON

Beispielantwort:

```json
{
    "subject": {
        "common_name": "mcs",
        "country": "de",
        "organization": "MCS",
        "organizational_unit": "dev",
        "locality": "Hattigen",
        "province": "NRW",
        "street_address": "Welperstraße 65",
        "postal_code": "45525",
        "names": [
            "de",
            "NRW",
            "Hattigen",
            "Welperstraße 65",
            "45525",
            "MCS",
            "dev",
            "mcs"
        ]
    },
    "issuer": {
        "common_name": "mcs",
        "country": "de",
        "organization": "MCS",
        "organizational_unit": "dev",
        "locality": "Hattigen",
        "province": "NRW",
        "street_address": "Welperstraße 65",
        "postal_code": "45525",
        "names": [
            "de",
            "NRW",
            "Hattigen",
            "Welperstraße 65",
            "45525",
            "MCS",
            "dev",
            "mcs"
        ]
    },
    "serial_number": "843198170162794019371705681989803412654",
    "not_before": "2023-08-02T13:49:58Z",
    "not_after": "2033-08-02T13:49:58Z",
    "sigalg": "SHA256WithRSA",
    "authority_key_id": "63:8F:F5:0C:04:5A:03:4C:7B:D1:9E:B6:A2:74:19:95:F4:C2:53:BB",
    "subject_key_id": "63:8F:F5:0C:04:5A:03:4C:7B:D1:9E:B6:A2:74:19:95:F4:C2:53:BB",
    "pem": "-----BEGIN CERTIFICATE-----\n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\nIqvyYJi0vaYu/FpwrcpBSrWjem1/FjS70L8E\n-----END CERTIFICATE-----\n"
}
```



## Client

### Client Zertifikat

Erzeugt ein neues Zertifikat für den Client. Benutzbar für  x509.KeyUsageKeyEncipherment, x509.KeyUsageDigitalSignature,, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth. Dieses Zertifikat ist erzeugt mit dem privaten Schlüssel des Clients und signiert über die CA des MV Services.

URL: GET /api/v1/clients/certificate

In; Template für das Zertifikat. (x509.CertificateRequest als PEM: Type CERTIFICATE REQUEST)

Out: Zertifikat als PEM Block

