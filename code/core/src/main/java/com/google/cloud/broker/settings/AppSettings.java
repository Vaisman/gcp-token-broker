// Copyright 2020 Google LLC
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.cloud.broker.settings;

import com.typesafe.config.ConfigFactory;
import com.typesafe.config.Config;

public class AppSettings {

    private AppSettings() {
    }

    public static final String GCP_PROJECT = "gcp-project";
    public static final String GSUITE_ADMIN = "gsuite-admin";
    public static final String AUTHORIZER_HOST = "authorizer.host";
    public static final String AUTHORIZER_PORT = "authorizer.port";
    public static final String LOGGING_LEVEL = "logging.level";
    public static final String SERVER_HOST = "server.host";
    public static final String SERVER_PORT = "server.port";
    public static final String TLS_ENABLED = "server.tls.enabled";
    public static final String TLS_CERTIFICATE_PATH = "server.tls.certificate-path";
    public static final String TLS_PRIVATE_KEY_PATH = "server.tls.private-key-path";
    public static final String SESSION_LOCAL_CACHE_TIME = "sessions.local-cache-time";
    public static final String SESSION_MAXIMUM_LIFETIME = "sessions.maximum-lifetime";
    public static final String SESSION_RENEW_PERIOD = "sessions.renew-period";
    public static final String PROXY_USERS = "proxy-users";
    public static final String SCOPES_WHITELIST = "scopes.whitelist";
    public static final String PROVIDER_BACKEND = "provider.backend";
    public static final String ACCESS_TOKEN_LOCAL_CACHE_TIME = "provider.access-tokens.local-cache-time";
    public static final String ACCESS_TOKEN_REMOTE_CACHE_TIME = "provider.access-tokens.remote-cache-time";
    public static final String HYBRID_USER_PROVIDER = "provider.hybrid.user-provider";
    public static final String JSON_FILE_CREDENTIALS_PROVIDER_BASE_DIR = "provider.json-file-credentials.base-dir";
    public static final String DATABASE_BACKEND = "database.backend";
    public static final String DATABASE_JDBC_URL = "database.jdbc.driver-url";
    public static final String REMOTE_CACHE = "remote-cache.backend";
    public static final String REDIS_CACHE_HOST = "remote-cache.redis.host";
    public static final String REDIS_CACHE_PORT = "remote-cache.redis.port";
    public static final String REDIS_CACHE_DB = "remote-cache.redis.db";
    public static final String OAUTH_CLIENT_ID = "oauth.client-id";
    public static final String OAUTH_CLIENT_SECRET = "oauth.client-secret";
    public static final String OAUTH_CLIENT_SECRET_JSON_PATH = "oauth.client-secret-json-path";
    public static final String AUTHENTICATION_BACKEND = "authentication.backend";
    public static final String KEYTABS = "authentication.spnego.keytabs";
    public static final String ENCRYPTION_BACKEND = "encryption.backend";
    public static final String ENCRYPTION_DEK_URI = "encryption.cloud-kms.dek-uri";
    public static final String ENCRYPTION_KEK_URI = "encryption.cloud-kms.kek-uri";
    public static final String USER_MAPPER = "user-mapping.mapper";
    public static final String USER_MAPPING_RULES = "user-mapping.rules";

    private static Config instance;
    static {
        reset(); // Initialize instance
    }

    public static Config getInstance() {
        return instance;
    }

    static void setInstance(Config newInstance) {
        instance = newInstance;
    }

    static void reset() {
        ConfigFactory.invalidateCaches();
        setInstance(ConfigFactory.load());
    }
}