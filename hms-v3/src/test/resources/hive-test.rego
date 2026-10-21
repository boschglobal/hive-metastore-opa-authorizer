package hms

import rego.v1

default database_allow = false
default table_allow = false
default partition_allow = false

database_allow if {
  input.resources.database.name = "new_db"
  input.privileges.writeRequiredPriv[0].priv = "CREATE"
}

table_allow if {
  input.resources.table.dbName = "new_db"
}

# The partition is sent as the Thrift Partition (dbName, tableName, values, sd, ...).
partition_allow if {
  input.resources.partition.dbName = "new_db"
  input.resources.partition.tableName = "partitioned_tbl"
  input.resources.partition.values[0] != "denied"
}