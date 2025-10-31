package hms

import rego.v1

default database_allow = false
default table_allow = false

database_allow if {
  input.resources.database.name = "new_db"
  input.privileges.writeRequiredPriv[0].priv = "CREATE"
}