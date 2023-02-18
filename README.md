# micro-vault

micro-vault microservice dead simple key management service without any golden rings, just simple and secure

## Wofür gibt es diesen Server?

Die Idee zu diesen Service entstand bei einem privaten Mikroservice Projekt. Dabei sollten bestimmte Daten zwischen Servicen über einen 3 Service (Message Broker) sicher ausgetauscht werden können. d.h. die Daten sollten für 3. und auch anderer nicht beteiligte Komponenten nicht einsehbar sein. Es besteht aber zwischen den komunizierenden Servicen keine direkte Verbindung. (Beide Service können sowohl zeitlich wie auch Räumlich getrennt sein.) 

Der Ansatz war ähnlich wie bei TLS. Es gibt einen dritten Vertrauten, dieser Service, der als Vermittler dient.

Ein Client wird zunächst auf den MicroVault Service eingerichtet. Dabei wird eine AccoutID und ein Secret generiert. Das Secret kann automatisch erneuert werden. Es kann aber auch statisch bleiben. 
Jeder Client wird dann zu Gruppen hinzu gefügt. Er kann nur die Zertifikate dieser Gruppen sehen. 

Beim Login generiert der Client automatisch ein RSA Zertifikat. Dieses wird dann für diesen Client im MV gespeichert. (Sitzungszertifikat) Dieses Zertifikat kann dann zur Verschlüsselten Kommunikation mit diesem Service verwendet werden. Jeder weitere Client einer der von diesem CLient angehörigen Gruppen, kann das Public Zertifikat dieses Services abrufen. 

Weiterhin kann jeder Client ein neues AES Verschlüsselungszertifikat im MS für einen Gruppe erstellen lassen. Dieses Erhält eine ID. Mit diesem Zertifikat kann dann jeder Client einer Gruppe Daten für diese Gruppe verschlüsseln und das Paket dann samt ID übertragen. Die Gegenstelle kann sich dann über die ID den AES Schlüssel zum Entschlüsseln besorgen, solange Sie ebenfalls zur gleichen Gruppe gehört. 

Sämtliche Kommunikation vom und zum MV ist per TLS verschlüsselt. 
Es gibt 2 Interface Bereiche, einmal der Admin Bereich für das Management und der Client Bereich für den Austausch. Später kann es noch einen Kommunikationsbereich geben, wo sich Client über Daten austauschen.   

## Speichermodelle

Es gibt 3 Speichermodell

### Memory only

Im Memory-only Modell werden alle Daten ausschließlich im Speicher gehalten. Wird der Service neu gestartet, werden alle Einstellungen neu generiert. Es findet keine dauerhafte Persistierung statt. Direkt nach dem Start kann zur einmaligen Initialisierung ein Playbook in den Server geladen werden. Dort können Gruppen und Clients definiert werden.      

### Filesystem

Alle Daten werden auf dem Filesystem gespeichert. Ein Playbook kann auch hier zur Initialisierung verwendet werden. Das Filesystem hat allerdings Vorrang.

### MongoDB

Alle Daten werden verschlüsselt in einer MongoDB abgelegt. Der Verschlüssellungschlüssel wird entweder per Passwort generiert (Passwort aus der Config bzw. Secret) oder per Environment übergeben.

### Multinodebetrieb

Im Multinodebetrieb werden alle Daten über ein eigenes Protokoll zu allen Nodes verteilt.  

## Kommunikationsablauf

### Usecase A: Client A möchte an alle Clients der Gruppe B eine verschlüsselte Nachricht schicken.

- Client A meldet sich mit AccessKey und Secret an -> MV gibt ein JWToken zurück
- Client fordert ein Gruppen-Verschlüssellungszertifikat an -> MV generiert für die Gruppe B einen AES Schlüssel und eine ID. Beides wird als Antwort zu Client A gesendet.
- Client verschlüsselt die Nachricht, fügt der Nachricht die ID hinzu und versendet das ganze.
- Client C der Gruppe B ruft die Nachricht ab.
- Client C meldet sich an MV an, -> erhält ein JWT
- Client C fordert den Schlüssel mit der ID an, -> MV sucht in allen Gruppen von Client C nach dem Schlüssel zu ID, liefert diesen dann zurück
- Client C entschlüsselt die Nachricht. 

### Usecase B: Client A möchte an Client B eine verschlüsselte Nachricht schicken

- Client A meldet sich mit AccessKey und Secret an -> MV gibt ein JWToken zurück
- Client fordert den Public Key von Client B an -> MV prüft ob A und B gemeinsame Gruppen haben. Public Key B wird als Antwort zu Client A gesendet.
- Client verschlüsselt die Nachricht und versendet das ganze.
- Client B ruft die Nachricht ab.
- Client B entschlüsselt die Nachricht mit persönlichem Schlüssel. 

## Playbook

Das Playbook kann per Config (Einstellung playbook file) oder per Commandline (--playbook -b) übergeben werden. Eine Übergabe ist auch einmalig nach dem Start per REST POST möglich. Bei Ausführung mehrere Optionen wird folgende Reihenfolge verwendet. Bei gleichen Einstellungen erfolgt ein Merge. 

**Reihenfolge:** Config -> Commandline -> REST

playbook.yaml

```yaml
groups:
  - message_a:
      name: message_a
      label: 
        de: Meldung_A
        en: message_a
  - message_b:
      name: message_b
      label: 
        de: Meldung_B
        en: message_b
clients:
  - source_a:
      accessKey: dasfgwkebtuiwebucewzn
      secret: sdbzdsuewizbtv9z
      secretRetention: -1
      groups:
        - message_a
        - message_b
  - source_b:
      accessKey: dshflvkewawtovwalszn
      secret: ashrbsekwabr
      secretRetention: -1
      groups:
        - message_a
   
```



# Admin Endpunkte

Im Adminbereich finden sich die Endpunkte zum anlegen eines Clients, Secreterneuerung, Gruppen-Administration. Wenn nicht anders vermerkt, sind die Endpunkte nur über einen angemeldeten User mit Adminrechten zu benutzen. Andere sind auch für angemeldete Clients benutzbar.

## Client CRUD

### Client erzeugen (Create)

Hiermit wird ein neuer Client erzeugt. 

In: Gruppen

Out: Access-Key, Secret

### Client Info (READ) *all 

Info über den Client 

Out: Accesskey, Secretablaufdatum, Gruppenzugehörigkeit

### Client Secreterneuerung (Update)

Hier wird ein für den CLient ein neues Secret angefordert. 

In: altes Secret

Out: neues Secret 

### Client löschen (Delete)

Löscht den Client vom MV Service

### Client Groups AD

Add, Delete fügt neue Gruppen zu einem Client hinzu, bzw. löscht mehere GRuppen eines Clients

## Gruppen CRUD

Crud Endpunkte für die Gruppen. 

### Gruppe anlegen (Create), Update(Update) und Löschen (Delete)

Verwaltung der Gruppen

### Gruppe lesen (Read) *all

die Gruppeninfos aller Gruppen sind für jeden angemeldeten Client lesbar.

## Playbook Post

Mit diesem Endpunkt kann ein Playbook nur einmal nach dem Start innerhalb einer in der Config einstellbaren Zeit hoch geladen werden. Dieses gilt dann als Basis für den weiteren Betrieb.  

# Client Endpunkte

## Client Login

Beim Clientlogin mit Accesskey und secret wird ein JWToken geniert, welches zur weiteren Identifizierung verwendet werden kann. 

Features:

- usage of Opentracing/jaeger
- gelf logging
- authorization with jwt
- cached healthcheck, livez and readyz endpoints
- https/ssl and http for payload and metrics/healthcheck
- metrics with Prometheus: https://prometheus.io/docs/guides/go-application/
- Docker build with builder and target image
- chi as the router framework
- go 1.18
- automatic config substitution 

## Configuration

In this template the configuration will be automatically loaded. You have the following options to set the service configuration file.

- default: the service will try to load the configuration from the `<userhome>/<servicename>/service.yaml`
- via Commandline: `-c <configfile>` will load the configuration from this file

IN the configuration file you can use `${}` macros for adding environment variables for the configuration itself. This will not work on the `secret.yaml`. The `secret.yaml` (if given in the configuration) will load a partial configuration from another file. (Mainly for separating credentials from the other configuration) Be aware, you manually have to merge both configuration in the `config.mergeSecret()` function.



## Prometheus integration

You can switch on the prometheus integration simply by adding 

```yaml
metrics:
  enable: true
```

to the service config.

### How to add a new counter?

Simply on the class, where you want to add a new counter (or something else) make a new variable with:

```go
var (
  postConfigCounter = promauto.NewCounter(prometheus.CounterOpts{
	 Name: "gomicro_post_config_total",
     Help: "The total number of post config requests",
  })
)
```

In the code where to count the events simply do an



```go
postConfigCounter.Inc()
```

 Thats all. More examples here: https://prometheus.io/docs/guides/go-application/