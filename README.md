# Hive Metastore Opa Authorizer

This project provides an Open Policy Agent (OPA) based authorization plugin for the Apache Hive Metastore. It enables fine-grained, policy-driven access control by delegating authorization decisions to OPA using flexible Rego policies. The authorizer is compatible with both Hive 3 and Hive 4, and can be easily integrated into your existing Hive Metastore deployment.

For information on how to contribute, see the [CONTRIBUTING.md](CONTRIBUTING.md) file.

## Installation
You can install this authorizer by downloading the appropriate release from the [GitHub Releases page](https://github.com/boschglobal/hive-metastore-opa-authorizer/releases). Choose the version that matches your Hive and Hadoop environment. After downloading, copy the `.jar` file into the `lib` directory of your Hive Metastore installation (typically `<HIVE_HOME>/lib`). Then restart the Hive Metastore service to load the new authorizer classes.

**Note:** The GitHub-based releases are built with JDK 21.

## How to enable this authorizer
In order to enable the Authorizer, configure the following settings. After that, HMS will check Authorization with OPA.

### Hive 3
```properties
hive.metastore.pre.event.listeners="com.bosch.bdps.hms3.OpaAuthorizationPreEventListener"
hive.security.metastore.authorization.manager="com.bosch.bdps.hms3.OpaBasedAuthorizationProvider"
```
### Hive 4
```properties
hive.metastore.pre.event.listeners="com.bosch.bdps.hms4.OpaAuthorizationPreEventListener"
hive.security.metastore.authorization.manager="com.bosch.bdps.hms4.OpaBasedAuthorizationProvider"
```

## Configuration
The authorizer can be configured with both environmental variables as well as Hive settings. Environment takes precedence.

| Option (Hive config) | Environmental Variable | Description | Default | Required |
| -------------------- | ---------------------- | ----------- | ------- | -------- |
| com.bosch.bdps.opa.authorization.base.endpoint | OPA_BASE_ENDPOINT | Endpoint for OPA | n/a | YES |
| com.bosch.bdps.opa.authorization.policy.url.database | OPA_POLICY_URL_DATABASE | Policy to check database authorization. | hms/database_allow | NO |
| com.bosch.bdps.opa.authorization.policy.url.table | OPA_POLICY_URL_TABLE | Policy to check table authorization. | hms/table_allow | NO |
| com.bosch.bdps.opa.authorization.policy.url.column | OPA_POLICY_URL_COLUMN | Policy to check column authorization. | hms/column_allow | NO |
| com.bosch.bdps.opa.authorization.policy.url.partition | OPA_POLICY_URL_PARTITION | Policy to check partition authorization. | hms/partition_allow | NO |
| com.bosch.bdps.opa.authorization.policy.url.user | OPA_POLICY_URL_USER | Policy to check user authorization. | hms/user_allow | NO |

---

## OPA Input Dictionary
When a request is authorized, a JSON dictionary is sent to OPA with the following structure:

```json
{
  "identity": {
    "username": "<user>",
    "groups": ["<group1>", "<group2>"]
  },
  "resources": {
    "database": null,
    "table": null,
    "partition": null,
    "columns": ["col1", "col2"]
  },
  "privileges": {
    "readRequiredPriv": [],
    "writeRequiredPriv": [],
    "inputs": null,
    "outputs": null
  }
}
```
- `identity`: Contains user information.
  - `username`: The name of the user.
  - `groups`: A list of groups the user belongs to.
- `resources`: Specifies the resources involved in the request.
  - `database`: The database object.
  - `table`: The table object.
  - `partition`: The partition object.
  - `columns`: A list of column names involved in the request.
- `privileges`: Details the privileges required for the request.
  - `readRequiredPriv`: A list of required read privileges.
  - `writeRequiredPriv`: A list of required write privileges.
  - `inputs`: Input tables for the request.
  - `outputs`: Output tables for the request.

---

## Example OPA Rego Rule
Below is a example Rego policy (see `examples/hive.rego`) that demonstrates how to handle the input dictionary sent from the authorizer:

```rego
package hms

default database_allow = false

default table_allow = false

database_allow if {
  input.identity.username == "my_user"
  input.resources.database.name == "test_db"
}

table_allow if {
  input.identity.username == "my_user1"
  input.resources.table.dbName == "test_db"
  input.resources.table.tableName == "test_table"
  input.privileges.readRequiredPriv[0].priv == "SELECT"
}
```

- `database_allow` grants access if the user is `my_user` and the database is `test_db`.
- `table_allow` grants access if the user is `my_user1`, the table is `test_table` in `test_db`, and the required privilege is `SELECT`.

You can adapt these rules to fit your authorization requirements. For more examples, see the `examples/` folder in this repository.

---

# Building
To build the authorizer and the images, follow the procedure below. Ensure you have the required tools installed.

## Requirements
- Java (OpenJDK 11 or newer)
- Maven
- Make

### On Debian-based systems
```shell
sudo apt-get update
sudo apt-get install make openjdk-11-jdk maven
```

### On RHEL-based systems
```shell
sudo dnf install make java-11-openjdk-devel maven
```

## Building the JARs
Use the Makefile to build for the desired Hive and Hadoop versions:
```shell
# Build jar for HMS v4
make HIVE_VERSION=4.0.0 HADOOP_VERSION=3.3.6

# Build jar for HMS v3
make HIVE_VERSION=3.1.3 HADOOP_VERSION=3.3.6
```

Alternatively, you can build directly with Maven from the main project directory or from each submodule:
```shell
# From the main directory, specifying Hive and Hadoop versions:
mvn clean package -Dhive.version=4.0.0 -Dhadoop.version=3.3.6 -f hms-v4/pom.xml

# Or for Hive 3:
mvn clean package -Dhive.version=3.1.3 -Dhadoop.version=3.3.6 -f hms-v3/pom.xml
```

## Running Tests
You can run all tests directly from the main project directory:
```shell
# Run all tests for all modules, with default versions
mvn test
```

Or run tests for a specific module:
```shell
# Run tests for HMS v4 module
mvn test -Dhive.version=4.0.0 -Dhadoop.version=3.3.6  -f hms-v4/pom.xml 

# Run tests for HMS v3 module
mvn test -Dhive.version=3.1.3 -Dhadoop.version=3.3.6 -f hms-v3/pom.xml
```

## Projects using this plugin

We would love to hear about real-world usage! If you are using this plugin in your project or organization, please add your project here via a pull request.

- *(Your project here!)*
