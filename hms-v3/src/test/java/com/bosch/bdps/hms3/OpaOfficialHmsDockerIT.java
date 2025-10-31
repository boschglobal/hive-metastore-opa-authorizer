package com.bosch.bdps.hms3;

import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.hive.metastore.HiveMetaStoreClient;
import org.apache.hadoop.hive.metastore.api.Database;
import org.apache.hadoop.hive.metastore.api.MetaException;
import org.apache.hadoop.hive.metastore.api.Table;
import org.apache.hadoop.hive.metastore.client.builder.CatalogBuilder;
import org.apache.hadoop.hive.metastore.client.builder.DatabaseBuilder;
import org.apache.hadoop.hive.metastore.client.builder.TableBuilder;
import org.apache.thrift.TException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.io.File;

import static org.junit.jupiter.api.Assertions.*;


public class OpaOfficialHmsDockerIT {

    private Network network;
    private GenericContainer<?> opaContainer; // This one will have the custom file
    private GenericContainer<?> hmsContainer;
    private GenericContainer<?> client;

    String jarPath = System.getProperty("shadedJar");
    String hiveVersion = System.getProperty("hiveVersion");

    String[] serviceOptsArr = new String[] {
            "-Dhive.metastore.pre.event.listeners=com.bosch.bdps.hms3.OpaAuthorizationPreEventListener",
            "-Dhive.security.metastore.authorization.manager=com.bosch.bdps.hms3.OpaBasedAuthorizationProvider",
            "-Dcom.bosch.bdps.opa.authorization.base.endpoint=http://opa-server:8181/v1/data"
    };

    @BeforeEach
    void setup() {
        network  = Network.newNetwork();

        String regoPath = new File("target/test-classes/hive-test.rego").getAbsolutePath();
        opaContainer = new GenericContainer<>(DockerImageName.parse("openpolicyagent/opa")).
                withNetwork(network).withNetworkAliases("opa-server").withExposedPorts(8181).
                withCopyFileToContainer(MountableFile.forHostPath(regoPath), "/policies/hive-test.rego").
                withCommand("run --server --log-level debug --addr :8181 /policies");

        hmsContainer = new GenericContainer<>(DockerImageName.parse("apache/hive:" + hiveVersion))
                .withEnv("SERVICE_NAME", "metastore").withExposedPorts(9083).withNetwork(network).withNetworkAliases("hive-metastore")
                .withEnv("OPA_BASE_ENDPOINT", "http://opa-server:8181/v1/data").withEnv("SERVICE_OPTS", String.join(" ", serviceOptsArr))
                .withCopyFileToContainer(MountableFile.forHostPath(jarPath), "/opt/hive/lib/hms-opa-authorizer.jar");

    }

    @AfterEach
    void cleanup() {
        if (opaContainer != null) {
            opaContainer.stop();
        }
        if (hmsContainer != null) {
            hmsContainer.stop();
        }
        if (network != null) {
            network.close(); // Clean up the network
        }
    }

    @Test
    void testDeny() throws IOException, InterruptedException, MetaException {
        opaContainer.start();
        hmsContainer.start();

        HiveConf  configuration = new HiveConf();
        configuration.set("hive.metastore.uris", "thrift://" + hmsContainer.getHost() + ":" + hmsContainer.getMappedPort(9083));
        HiveMetaStoreClient client = new HiveMetaStoreClient(configuration);

        // We're supposed to fail when dropping default
        try {
            client.dropDatabase("default");
        } catch (TException e) {
            assertTrue(e.getMessage().contains("Request denied due to hms/database_allow authorization policy."));
        }

        // We're allowed to create "new_db", according to OPA rules
        try {
            DatabaseBuilder databaseBuilder = new DatabaseBuilder();
            databaseBuilder.setName("new_db");
            client.createDatabase(databaseBuilder.build(configuration));
            assertTrue(client.getAllDatabases().contains("new_db"));
        } catch (TException e) {
            System.out.println(e);
            fail();
        }

        client.close();
    }

    @Test
    void testAllow() throws MetaException {
        opaContainer.start();
        hmsContainer.start();

        HiveConf  configuration = new HiveConf();
        configuration.set("hive.metastore.uris", "thrift://" + hmsContainer.getHost() + ":" + hmsContainer.getMappedPort(9083));
        HiveMetaStoreClient client = new HiveMetaStoreClient(configuration);

        // We're allowed to create "new_db", according to OPA rules
        try {
            DatabaseBuilder databaseBuilder = new DatabaseBuilder();
            databaseBuilder.setName("new_db");
            client.createDatabase(databaseBuilder.build(configuration));
            assertTrue(client.getAllDatabases().contains("new_db"));
        } catch (TException e) {
            System.out.println(e);
            fail();
        }

        client.close();
    }
}
