# micro-vault

micro-vault microservice dead simple key management service without any golden rings, just simple and secure

## Wofür gibt es diesen Server?

Die Idee zu diesen Service entstand bei einem privaten Mikroservice Projekt. Dabei sollten bestimmte Daten zwischen Services über einen 3 Service (Message Broker) sicher ausgetauscht werden können. d.h. die Daten sollten für andere nicht beteiligte Komponenten nicht einsehbar sein. Es besteht aber zwischen den kommunizierenden Services keine direkte Verbindung. (Beide Service können sowohl zeitlich wie auch Räumlich getrennt sein.) 

Der Ansatz war ähnlich wie bei TLS. Es gibt einen dritten Vertrauten, dieser Service, der als Vermittler dient.

Ein Client wird zunächst auf den MicroVault Service eingerichtet. Dabei wird eine AccoutID und ein Secret generiert. Das Secret kann automatisch erneuert werden. Es kann aber auch statisch bleiben. 
Jeder Client wird dann zu Gruppen hinzu gefügt. Er kann nur die Zertifikate dieser Gruppen sehen. 

Beim Login generiert der Client automatisch ein RSA Zertifikat. Dieses wird dann für diesen Client im MV gespeichert. (Sitzungszertifikat) Dieses Zertifikat kann dann zur direkten verschlüsselten Kommunikation mit diesem Service verwendet werden. Jeder weitere Client einer der von diesem CLient angehörigen Gruppen, kann das Public Zertifikat dieses Services abrufen. 

Weiterhin kann jeder Client ein neues AES Verschlüsselungszertifikat im MS für einen Gruppe erstellen lassen. Dieses Erhält eine ID. Mit diesem Zertifikat kann dann jeder Client einer Gruppe Daten für diese Gruppe verschlüsseln und das Paket dann samt ID übertragen. Die Gegenstelle kann sich dann über die ID den AES Schlüssel zum Entschlüsseln besorgen, solange Sie ebenfalls zur gleichen Gruppe gehört. 

Als 3. Feature kann man über einen Datenbereich eine Signatur bilden und diese auch wieder prüfen.

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
- Client B entschlüsselt die Nachricht mit persönlichem Schlüssel. 

### Usecase 3: Client A möchte Daten einer Nachricht mit einer Signatur versehen

- Client A meldet sich mit AccessKey und Secret an -> MV gibt ein JWToken zurück
- Client A bildet mit seinem privaten Schlüssel über die Daten eine Signatur
- Client A versendet die Nachricht, die Signatur und seinen Namen.
- Client B ruft die Nachricht, Signatur und den Namen ab.
- Client B fordert den öffentlichen Schlüssel von Client A an -> MV prüft die gemeinsamen Gruppen 
- Client B prüft die Signatur. 

## Playbook

Das Playbook kann per Config (Einstellung playbook file) oder per Commandline (--playbook -b) übergeben werden. Eine Übergabe ist auch einmalig nach dem Start per REST POST möglich. Bei Ausführung mehrere Optionen wird folgende Reihenfolge verwendet. Bei gleichen Einstellungen erfolgt ein Merge. 

**Reihenfolge:** Config -> Commandline -> REST

playbook.json

```json
{
    "groups": [
        {
            "name": "group1",
            "label":
            {
                "en": "Group 1",
                "de": "Gruppe 1"
            }
        },
        {
            "name": "group3",
            "label":
            {
                "en": "Group 3",
                "de": "Gruppe 3"
            }
        },
        {
            "name": "group4",
            "label":
            {
                "en": "Group 4",
                "de": "Gruppe 4"
            }
        }
    ],
    "clients": [
        {
            "name": "tester1",
            "accesskey": "12345678",
            "secret": "yxcvb",
            "groups": [
                "group1",
                "group2",
                "group4"
            ]
        },
        {
            "name": "tester2",
            "accesskey": "87654321",
            "secret": "yxcvb",
            "groups": [
                "group2",
                "group4"
            ]
        },
        {
            "name": "tester3",
            "accesskey": "345678",
            "secret": "yxcvb",
            "groups": [
                "group3"
            ]
        }
    ]
}
   
```

Aus Sicherheitsgründen gibt keinen Weg, ein Playbook aus einem laufenden Server zu exportieren.  Allerdings gibt es einen Commandozeilen Parameter mit dem das Binary eine playbook.json aus einer Installation erzeugt. Dazu muss das Binary mit den gleichen Einstellungen wie der Service gestartet werden.  

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

POST: /api/v1/vault/login

Body: {}

Beim Clientlogin mit Accesskey und secret wird ein JWToken geniert, welches zur weiteren Identifizierung verwendet werden muss. 

