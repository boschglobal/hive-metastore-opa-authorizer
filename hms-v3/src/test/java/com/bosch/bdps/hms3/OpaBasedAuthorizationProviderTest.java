/*
 * Copyright 2025 the Hive Metastore Opa Authorizer Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.bosch.bdps.hms3;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.metastore.api.Database;
import org.apache.hadoop.hive.ql.metadata.AuthorizationException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.apache.hadoop.hive.ql.metadata.Partition;
import org.apache.hadoop.hive.ql.metadata.Table;
import org.apache.hadoop.hive.ql.security.HiveAuthenticationProvider;
import org.apache.hadoop.hive.ql.security.authorization.Privilege;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HiveAuthzPluginException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.anyMap;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class OpaBasedAuthorizationProviderTest {

    @InjectMocks
    private OpaBasedAuthorizationProvider authorizationProvider;

    @Mock
    private HiveAuthenticationProvider authenticationProvider;

    @Mock
    private OpaBasedAuthorizationProvider.OpaHttpClient opaClient;

    @Captor
    ArgumentCaptor<Map<String, Object>> captor;

    private final Configuration configuration = new Configuration();

    @BeforeEach
    public void setUp() throws HiveException {
        when(authenticationProvider.getUserName()).thenReturn("testUser");
        when(authenticationProvider.getGroupNames()).thenReturn(Collections.singletonList("testGroup"));

        authorizationProvider.setAuthenticator(authenticationProvider);

        configuration.set("com.bosch.bdps.opa.authorization.base.endpoint", "http://localhost:8181/v1/data");

        authorizationProvider.init(configuration);
        authorizationProvider.setConf(configuration);

        authorizationProvider.setOpa(opaClient);
    }

    @Test
    public void testAuthorizeUserLevel() throws HiveException, AuthorizationException, Exception {
        Privilege[] readPriv = new Privilege[]{Privilege.SELECT};
        Privilege[] writePriv = new Privilege[]{Privilege.INSERT};

        when(opaClient.check(eq("hms/user_allow"), anyMap())).thenReturn(true);

        authorizationProvider.authorize(readPriv, writePriv);

        verify(opaClient).check(eq("hms/user_allow"), captor.capture());
        HashMap<?, ?> identity = (HashMap<?, ?>) captor.getValue().get("identity");
        assertEquals("testUser", identity.get("username"));
        assertEquals(Collections.singletonList("testGroup"), identity.get("groups"));

        HashMap<?, ?> privileges = (HashMap<?, ?>) captor.getValue().get("privileges");
        assertEquals(readPriv, privileges.get("readRequiredPriv"));
        assertEquals(writePriv, privileges.get("writeRequiredPriv"));
    }

    @Test
    public void testAuthorizeDatabase() throws HiveException, AuthorizationException, Exception {
        Database db = mock(Database.class);
        when(db.getName()).thenReturn("testDB");
        Privilege[] readPriv = new Privilege[]{Privilege.SELECT};
        Privilege[] writePriv = new Privilege[]{Privilege.INSERT};

        when(opaClient.check(eq("hms/database_allow"), anyMap())).thenReturn(true);

        authorizationProvider.authorize(db, readPriv, writePriv);

        verify(opaClient).check(eq("hms/database_allow"), captor.capture());
        HashMap<?, ?> identity = (HashMap<?, ?>) captor.getValue().get("identity");
        assertEquals("testUser", identity.get("username"));
        assertEquals(Collections.singletonList("testGroup"), identity.get("groups"));

        HashMap<?, ?> resources = (HashMap<?, ?>) captor.getValue().get("resources");
        assertEquals(db, resources.get("database"));

        HashMap<?, ?> privileges = (HashMap<?, ?>) captor.getValue().get("privileges");
        assertEquals(readPriv, privileges.get("readRequiredPriv"));
        assertEquals(writePriv, privileges.get("writeRequiredPriv"));
    }

    @Test
    public void testAuthorizeTable() throws HiveException, AuthorizationException, Exception {
        Table table = mock(Table.class);
        Privilege[] readPriv = new Privilege[]{Privilege.SELECT};
        Privilege[] writePriv = new Privilege[]{Privilege.INSERT};

        when(opaClient.check(eq("hms/table_allow"), anyMap())).thenReturn(true);

        authorizationProvider.authorize(table, readPriv, writePriv);

        verify(opaClient).check(eq("hms/table_allow"), captor.capture());
        HashMap<?, ?> identity = (HashMap<?, ?>) captor.getValue().get("identity");
        assertEquals("testUser", identity.get("username"));
        assertEquals(Collections.singletonList("testGroup"), identity.get("groups"));

        HashMap<?, ?> resources = (HashMap<?, ?>) captor.getValue().get("resources");
        assertEquals(table.getTTable(), resources.get("table"));

        HashMap<?, ?> privileges = (HashMap<?, ?>) captor.getValue().get("privileges");
        assertEquals(readPriv, privileges.get("readRequiredPriv"));
        assertEquals(writePriv, privileges.get("writeRequiredPriv"));

    }

    @Test
    public void testAuthorizePartition() throws HiveException, AuthorizationException, Exception {
        Partition partition = mock(Partition.class);
        Privilege[] readPriv = new Privilege[]{Privilege.SELECT};
        Privilege[] writePriv = new Privilege[]{Privilege.INSERT};

        when(opaClient.check(eq("hms/partition_allow"), anyMap())).thenReturn(true);

        authorizationProvider.authorize(partition, readPriv, writePriv);

        verify(opaClient).check(eq("hms/partition_allow"), captor.capture());
        HashMap<?, ?> identity = (HashMap<?, ?>) captor.getValue().get("identity");
        assertEquals("testUser", identity.get("username"));
        assertEquals(Collections.singletonList("testGroup"), identity.get("groups"));

        HashMap<?, ?> resources = (HashMap<?, ?>) captor.getValue().get("resources");
        assertEquals(partition, resources.get("partition"));

        HashMap<?, ?> privileges = (HashMap<?, ?>) captor.getValue().get("privileges");
        assertEquals(readPriv, privileges.get("readRequiredPriv"));
        assertEquals(writePriv, privileges.get("writeRequiredPriv"));
    }

    @Test
    public void testAuthorizeColumns() throws HiveException, AuthorizationException, Exception {
        Table table = mock(Table.class);
        Partition partition = mock(Partition.class);
        List<String> columns = Collections.singletonList("column1");
        Privilege[] readPriv = new Privilege[]{Privilege.SELECT};
        Privilege[] writePriv = new Privilege[]{Privilege.INSERT};

        when(opaClient.check(anyString(), anyMap())).thenReturn(true);

        authorizationProvider.authorize(table, partition, columns, readPriv, writePriv);

        verify(opaClient).check(eq("hms/column_allow"), captor.capture());
        HashMap<?, ?> identity = (HashMap<?, ?>) captor.getValue().get("identity");
        assertEquals("testUser", identity.get("username"));
        assertEquals(Collections.singletonList("testGroup"), identity.get("groups"));

        HashMap<?, ?> resources = (HashMap<?, ?>) captor.getValue().get("resources");
        assertEquals(table.getTTable(), resources.get("table"));
        assertEquals(partition, resources.get("partition"));
        assertEquals(columns, resources.get("columns"));

        HashMap<?, ?> privileges = (HashMap<?, ?>) captor.getValue().get("privileges");
        assertEquals(readPriv, privileges.get("readRequiredPriv"));
        assertEquals(writePriv, privileges.get("writeRequiredPriv"));
    }

    @Test
    public void testAuthorizationDenied() throws Exception {
        Table table = mock(Table.class);
        Partition partition = mock(Partition.class);
        List<String> columns = Collections.singletonList("column1");
        Privilege[] readPriv = new Privilege[]{};
        Privilege[] writePriv = new Privilege[]{};

        when(opaClient.check(anyString(), anyMap())).thenReturn(false);

        assertThrows(AuthorizationException.class, () -> {
            authorizationProvider.authorize(table, partition, columns, readPriv, writePriv);
        });
    }

    @Test
    public void testAuthorizationException() throws Exception {
        Table table = mock(Table.class);
        Partition partition = mock(Partition.class);
        List<String> columns = Collections.singletonList("column1");
        Privilege[] readPriv = new Privilege[]{Privilege.SELECT};
        Privilege[] writePriv = new Privilege[]{Privilege.INSERT};

        when(opaClient.check(anyString(), anyMap())).thenThrow(new Exception("OPA error"));

        assertThrows(HiveException.class, () -> {
            authorizationProvider.authorize(table, partition, columns, readPriv, writePriv);
        });
    }

    @Test
    public void testGetHivePolicyProvider() throws HiveAuthzPluginException {
        assertNull(authorizationProvider.getHivePolicyProvider());
    }

    @Test
    public void testGetConf() {
        assertEquals(configuration, authorizationProvider.getConf());
    }

    @Test
    public void testGetAuthenticator() {
        assertEquals(authenticationProvider, authorizationProvider.getAuthenticator());
    }
}
