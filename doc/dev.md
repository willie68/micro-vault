use microvault
db.createUser({ user: "microvault", pwd: "yxcvb", roles: [ "readWrite", "dbAdmin", { role: "dbOwner", db: "microvault" } ]})
