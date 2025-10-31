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
import org.apache.hadoop.hive.metastore.IHMSHandler;
import org.apache.hadoop.hive.metastore.api.Database;
import org.apache.hadoop.hive.ql.metadata.AuthorizationException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.apache.hadoop.hive.ql.metadata.Partition;
import org.apache.hadoop.hive.ql.metadata.Table;
import org.apache.hadoop.hive.ql.security.HiveAuthenticationProvider;
import org.apache.hadoop.hive.ql.security.authorization.HiveMetastoreAuthorizationProvider;
import org.apache.hadoop.hive.ql.security.authorization.Privilege;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HiveAuthzPluginException;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HivePolicyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.Arrays;
import java.util.Collections;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import static java.util.Objects.requireNonNull;

/**
* The class OpaBasedAuthorizationProvider is responsible for authorizing requests
 */
public class OpaBasedAuthorizationProvider implements HiveMetastoreAuthorizationProvider {

    public static final Logger LOG = LoggerFactory.getLogger(OpaBasedAuthorizationProvider.class);
    private HiveAuthenticationProvider authenticationProvider;
    private Configuration config;
    private OpaHttpClient opa;

    private String tableAuthResource;
    private String columnAuthResource;
    private String databaseAuthResource;
    private String partitionAuthResource;
    private String userLevelAuthResource;


    void setOpa(OpaHttpClient opa) {
        this.opa = opa;
    }


    @Override
    public void setMetaStoreHandler(IHMSHandler ihmsHandler) {

    }

    @Override
    public void authorizeAuthorizationApiInvocation() throws HiveException, AuthorizationException {

    }

    @Override
    public void init(Configuration configuration) throws HiveException {
        this.config = requireNonNull(configuration, "Configuration is null");
    }

    @Override
    public HiveAuthenticationProvider getAuthenticator() {
        return this.authenticationProvider;
    }

    @Override
    public void setAuthenticator(HiveAuthenticationProvider hiveAuthenticationProvider) {
        this.authenticationProvider = requireNonNull(hiveAuthenticationProvider, "HiveAuthenticationProvider is null");
        LOG.trace("Setting authenticator to: {}", hiveAuthenticationProvider);
        LOG.trace("User requesting auth: {}", hiveAuthenticationProvider.getUserName());
        LOG.trace("Group requesting auth: {}", hiveAuthenticationProvider.getGroupNames());     
    }

    @Override
    // Authorization user level privileges.
    public void authorize(Privilege[] readRequiredPriv, Privilege[] writeRequiredPriv) throws HiveException, AuthorizationException {
        LOG.debug("Requesting authorization (user level): readRequiredPriv={}, writeRequiredPriv={}",
                Arrays.toString(readRequiredPriv), Arrays.toString(writeRequiredPriv));

        Map<String, Object> parameters = new HashMap<>();
        parameters.put("readRequiredPriv", readRequiredPriv);
        parameters.put("writeRequiredPriv", writeRequiredPriv);

        this.checkOpaAuthorization(this.userLevelAuthResource, parameters);
    }

    @Override
    // Authorization privileges against a database object.
    public void authorize(Database db, Privilege[] readRequiredPriv, Privilege[] writeRequiredPriv) throws HiveException, AuthorizationException {
        LOG.debug("Requesting authorization (database): database={}, readRequiredPriv= {}, writeRequiredPriv= {}",
                db.getName(), Arrays.toString(readRequiredPriv), Arrays.toString(writeRequiredPriv));

        Map<String, Object> parameters = new HashMap<>();
        parameters.put("database", db);
        parameters.put("readRequiredPriv", readRequiredPriv);
        parameters.put("writeRequiredPriv", writeRequiredPriv);

        this.checkOpaAuthorization(this.databaseAuthResource, parameters);
    }

    @Override
    // Authorization privileges against a hive table object.
    public void authorize(Table table, Privilege[] readRequiredPriv, Privilege[] writeRequiredPriv) throws HiveException, AuthorizationException {
        LOG.debug("Requesting authorization (table): table={}, readRequiredPriv= {}, writeRequiredPriv= {}",
                table, Arrays.toString(readRequiredPriv), Arrays.toString(writeRequiredPriv));

        Map<String, Object> parameters = new HashMap<>();
        parameters.put("table", table.getTTable());
        parameters.put("readRequiredPriv", readRequiredPriv);
        parameters.put("writeRequiredPriv", writeRequiredPriv);

        this.checkOpaAuthorization(this.tableAuthResource, parameters);
    }

    @Override
    // Authorization privileges against a hive partition object.
    public void authorize(Partition part, Privilege[] readRequiredPriv, Privilege[] writeRequiredPriv) throws HiveException, AuthorizationException {
        LOG.debug("Requesting authorization (partition): part={}, readRequiredPriv={}, writeRequiredPriv={}",
                part, Arrays.toString(readRequiredPriv), Arrays.toString(writeRequiredPriv));

        Map<String, Object> parameters = new HashMap<>();
        parameters.put("partition", part);
        parameters.put("readRequiredPriv", readRequiredPriv);
        parameters.put("writeRequiredPriv", writeRequiredPriv);

        this.checkOpaAuthorization(this.partitionAuthResource, parameters);
    }

    @Override
    // Authorization privileges against a list of columns.
    public void authorize(Table table, Partition part, List<String> columns, Privilege[] readRequiredPriv, Privilege[] writeRequiredPriv) throws HiveException, AuthorizationException {
        LOG.debug("Requesting authorization (columns): table= {}, part={}, columns={}, readRequiredPriv={}, writeRequiredPriv={}",
                table, part, columns, Arrays.toString(readRequiredPriv), Arrays.toString(writeRequiredPriv));

        Map<String, Object> parameters = new HashMap<>();
        parameters.put("table", table.getTTable());
        parameters.put("partition", part);
        parameters.put("columns", columns);
        parameters.put("readRequiredPriv", readRequiredPriv);
        parameters.put("writeRequiredPriv", writeRequiredPriv);

        this.checkOpaAuthorization(this.columnAuthResource, parameters);
    }

    @Override
    public HivePolicyProvider getHivePolicyProvider() throws HiveAuthzPluginException {
        return null;
    }

    @Override
    public void setConf(Configuration configuration) {
        this.config = requireNonNull(configuration, "Configuration is null");
        String configOpaBaseEndpoint = System.getenv().getOrDefault("OPA_BASE_ENDPOINT", configuration.get("com.bosch.bdps.opa.authorization.base.endpoint"));
        String opaBaseEndpoint = requireNonNull(configOpaBaseEndpoint, "OPA_BASE_ENDPOINT is not set");

        this.tableAuthResource = this.getPolicyUrl("table");
        this.databaseAuthResource = this.getPolicyUrl("database");
        this.columnAuthResource = this.getPolicyUrl("column");
        this.partitionAuthResource = this.getPolicyUrl("partition");
        this.userLevelAuthResource = this.getPolicyUrl("user");

        this.opa = new OpaHttpClient(opaBaseEndpoint);
    }

    private String getPolicyUrl(String type) {
        String endpoint = System.getenv().getOrDefault("OPA_POLICY_URL_" + type.toUpperCase(),
                this.config.get("com.bosch.bdps.opa.authorization.policy.url." + type.toLowerCase(), "hms/" + type.toLowerCase() + "_allow"));

        LOG.debug("Setting endpoint for type={} to: {}", type, endpoint);
        return endpoint;
    }

    @Override
    public Configuration getConf() {
        return this.config;
    }

    private void checkOpaAuthorization(String path, Map<String, Object> input) throws AuthorizationException, HiveException {
        // Construct request body. Encapsulate "identity", "resource" and "privileges"
        // so they can be easier used in the opa rego rules.
        Map<String, Object> identityMap = new HashMap<>();
        identityMap.put("username", this.authenticationProvider.getUserName());
        identityMap.put("groups", this.authenticationProvider.getGroupNames());

        // If keys are not defined, HashMap.get(...) returns null.
        // This ensures that each and every key is present in the request.
        Map<String, Object> resourceMap = new HashMap<>();
        resourceMap.put("database", input.get("database"));
        resourceMap.put("table", input.get("table"));
        resourceMap.put("partition", input.get("partition"));
        resourceMap.put("columns", input.get("columns"));

        Map<String, Object> privilegeMap = new HashMap<>();
        privilegeMap.put("readRequiredPriv", input.get("readRequiredPriv"));
        privilegeMap.put("writeRequiredPriv", input.get("writeRequiredPriv"));
        privilegeMap.put("inputs", input.get("inputs"));
        privilegeMap.put("outputs", input.get("outputs"));

        Map<String, Object> finalRequest = new HashMap<>();
        finalRequest.put("identity", identityMap);
        finalRequest.put("resources", resourceMap);
        finalRequest.put("privileges", privilegeMap);

        boolean allowed;

        requireNonNull(opa, "OPA client is not initialized");
        try {
            allowed = this.opa.check(path, finalRequest);
        } catch (Exception e) {
            // Note that OPAException usually wraps other exception types, in
            // case you need to do more complex error handling.
            LOG.error("Exception while making request against OPA: {}", e.getMessage());
            throw new HiveException("Error during OPA authorization", e);
        }

        LOG.debug("Result from OPA: {}", allowed);

        if (!allowed) {
            throw new AuthorizationException("Request denied due to " + path + " authorization policy.");
        }
    }

    // Minimal OPA HTTP client implementation
    public static class OpaHttpClient {
        private final String baseUrl;
        private final ObjectMapper objectMapper = new ObjectMapper();

        public OpaHttpClient(String baseUrl) {
            this.baseUrl = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
        }

        public boolean check(String path, Map<String, Object> input) throws Exception {
            String url = baseUrl + path;
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            String json = objectMapper.writeValueAsString(Collections.singletonMap("input", input));
            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.getBytes(StandardCharsets.UTF_8));
            }
            int code = conn.getResponseCode();
            if (code != 200) {
                throw new RuntimeException("OPA returned non-200: " + code);
            }
            JsonNode node = objectMapper.readTree(conn.getInputStream());
            JsonNode result = node.get("result");
            if (result == null || !result.isBoolean()) {
                LOG.debug(node.toPrettyString());
                throw new RuntimeException("OPA response missing boolean 'result'");
            }
            return result.asBoolean();
        }
    }
}
