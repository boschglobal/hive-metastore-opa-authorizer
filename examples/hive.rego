package hms

import rego.v1

default database_allow = false
default table_allow = false

database_allow if {
  input.identity.username = "my_user"
  input.resources.database.name = "test_db"
}

table_allow if {
  input.identity.username = "my_user1"
  input.resources.table.dbName = "test_db"
  input.resources.table.tableName = "test_table"
  input.privileges.readRequiredPriv[0].priv = "SELECT"
}