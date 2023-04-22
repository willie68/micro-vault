Mongo preparation
use microvault
db.createUser({ user: "microvault", pwd: "yxcvb", roles: [ "readWrite", "dbAdmin", { role: "dbOwner", db: "microvault" } ]})
db.objects.createIndex( { "class": 1 , "identifier": 1} )

use microvault_test
db.createUser({ user: "microvault", pwd: "yxcvb", roles: [ "readWrite", "dbAdmin", { role: "dbOwner", db: "microvault_test" } ]})
db.objects.createIndex( { "class": 1 , "identifier": 1} )

Using golang as CA
https://medium.com/@shaneutt/create-sign-x509-certificates-in-golang-8ac4ae49f903
