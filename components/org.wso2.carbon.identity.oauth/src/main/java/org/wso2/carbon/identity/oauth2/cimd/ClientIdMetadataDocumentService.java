/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.cimd;

import com.nimbusds.jose.util.JSONObjectUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.conn.util.InetAddressUtils;
import org.wso2.carbon.identity.application.mgt.ApplicationMgtUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.oauth2.cimd.ClientIdMetadataDocumentException.ErrorMessage.CIMD_DISABLED;
import static org.wso2.carbon.identity.oauth2.cimd.ClientIdMetadataDocumentException.ErrorMessage.INVALID_CLIENT_AUTHENTICATION;
import static org.wso2.carbon.identity.oauth2.cimd.ClientIdMetadataDocumentException.ErrorMessage.INVALID_CLIENT_ID_URL;
import static org.wso2.carbon.identity.oauth2.cimd.ClientIdMetadataDocumentException.ErrorMessage.INVALID_GRANT_TYPES;
import static org.wso2.carbon.identity.oauth2.cimd.ClientIdMetadataDocumentException.ErrorMessage.INVALID_REDIRECT_URI;
import static org.wso2.carbon.identity.oauth2.cimd.ClientIdMetadataDocumentException.ErrorMessage.NO_MATCHING_DOCUMENT;
import static org.wso2.carbon.identity.oauth2.cimd.ClientIdMetadataDocumentException.ErrorMessage.VALUE_TOO_LONG;

/**
 * Previews a Client ID Metadata Document: retrieves it, validates it and returns the values to register. Stores
 * nothing.
 */
public class ClientIdMetadataDocumentService {

    private static final Log LOG = LogFactory.getLog(ClientIdMetadataDocumentService.class);

    static final String ENABLED_CONFIG = "OAuth.ClientIdMetadataDocumentSupported";

    static final String AUTH_METHOD_NONE = "none";
    static final String AUTH_METHOD_PRIVATE_KEY_JWT = "private_key_jwt";
    static final String GRANT_AUTHORIZATION_CODE = "authorization_code";
    static final String GRANT_REFRESH_TOKEN = "refresh_token";
    private static final List<String> SUPPORTED_GRANTS = Arrays.asList(GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN);

    private static final String HTTPS = "https";
    private static final String HTTP = "http";
    private static final int HTTPS_PORT = 443;
    private static final String IPV4_LOOPBACK = "127.0.0.1";
    private static final String IPV6_LOOPBACK = "[::1]";
    private static final String IPV4_LOOPBACK_PREFIX = HTTP + "://" + IPV4_LOOPBACK;
    private static final String CALLBACK_URL_REGEXP_PREFIX = "regexp=";
    private static final String REGEX_SPECIAL_CHARACTERS = "[.*+?^${}()|\\[\\]\\\\]";

    // Column sizes: IDN_OAUTH_CONSUMER_APPS.CONSUMER_KEY, SP_METADATA.VALUE, IDN_OAUTH_CONSUMER_APPS.CALLBACK_URL,
    // SP_APP.APP_NAME and SP_APP.ACCESS_URL.
    static final int MAX_CLIENT_ID_LENGTH = 255;
    static final int MAX_JWKS_URI_LENGTH = 255;
    static final int MAX_CALLBACK_URL_LENGTH = 2048;
    static final int MAX_CLIENT_NAME_LENGTH = 255;
    static final int MAX_CLIENT_URI_LENGTH = 1024;

    private final ClientIdMetadataDocumentFetcher fetcher;

    public ClientIdMetadataDocumentService() {

        this(new ClientIdMetadataDocumentFetcher());
    }

    ClientIdMetadataDocumentService(ClientIdMetadataDocumentFetcher fetcher) {

        this.fetcher = fetcher;
    }

    /**
     * Retrieve and validate the document at a Client Identifier URL.
     *
     * @param clientId Client Identifier URL.
     * @return Values to register.
     * @throws ClientIdMetadataDocumentException If CIMD is disabled, or the URL or the document is not accepted.
     */
    public ClientIdMetadataDocument preview(String clientId) throws ClientIdMetadataDocumentException {

        if (!Boolean.parseBoolean(IdentityUtil.getProperty(ENABLED_CONFIG))) {
            throw new ClientIdMetadataDocumentException(CIMD_DISABLED);
        }
        URI clientIdUri = validateClientIdUrl(clientId);
        Map<String, Object> document = parse(clientId, fetcher.fetch(clientId));

        // Until client_id matches, the response may not be a document at all, so it gets the generic error.
        if (!clientId.equals(document.get("client_id"))) {
            LOG.debug("Client ID Metadata Document not accepted: client_id does not match the URL.");
            throw new ClientIdMetadataDocumentException(NO_MATCHING_DOCUMENT);
        }

        List<String> redirectUris = validateRedirectUris(clientIdUri, document.get("redirect_uris"));
        if (document.containsKey("client_secret") || document.containsKey("client_secret_expires_at")) {
            throw new ClientIdMetadataDocumentException(INVALID_CLIENT_AUTHENTICATION);
        }
        Object authMethod = document.get("token_endpoint_auth_method");
        String jwksUri = null;
        if (AUTH_METHOD_PRIVATE_KEY_JWT.equals(authMethod)) {
            jwksUri = validateJwksUri(document);
        } else if (!AUTH_METHOD_NONE.equals(authMethod)) {
            // An absent method means client_secret_basic (RFC 7591), which is not supported.
            throw new ClientIdMetadataDocumentException(INVALID_CLIENT_AUTHENTICATION);
        }
        List<String> grantTypes = narrowGrantTypes(document.get("grant_types"));

        if (buildCallbackUrl(redirectUris).length() > MAX_CALLBACK_URL_LENGTH) {
            throw new ClientIdMetadataDocumentException(VALUE_TOO_LONG);
        }
        return new ClientIdMetadataDocument(clientId, getClientName(document, clientIdUri),
                getClientUri(document), redirectUris, (String) authMethod, jwksUri, grantTypes);
    }

    private static URI validateClientIdUrl(String clientId) throws ClientIdMetadataDocumentException {

        if (StringUtils.isBlank(clientId)) {
            throw new ClientIdMetadataDocumentException(INVALID_CLIENT_ID_URL);
        }
        URI uri;
        try {
            uri = new URI(clientId);
        } catch (URISyntaxException e) {
            throw new ClientIdMetadataDocumentException(INVALID_CLIENT_ID_URL, e);
        }
        // Only the default https port, so a preview cannot be used to probe other ports.
        if (!HTTPS.equals(uri.getScheme()) || !isDnsHost(uri.getHost()) || !isDefaultHttpsPort(uri)
                || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || StringUtils.isEmpty(uri.getPath()) || hasDotSegment(uri.getPath())) {
            throw new ClientIdMetadataDocumentException(INVALID_CLIENT_ID_URL);
        }
        if (clientId.getBytes(StandardCharsets.UTF_8).length > MAX_CLIENT_ID_LENGTH) {
            throw new ClientIdMetadataDocumentException(VALUE_TOO_LONG);
        }
        return uri;
    }

    private static Map<String, Object> parse(String clientId, String body) throws ClientIdMetadataDocumentException {

        Map<String, Object> document = null;
        try {
            document = JSONObjectUtils.parse(body);
        } catch (ParseException e) {
            // Handled below with a null document.
        }
        // A JSON null parses to null.
        if (document == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client ID Metadata Document from " + clientId + " not accepted: not a JSON object.");
            }
            throw new ClientIdMetadataDocumentException(NO_MATCHING_DOCUMENT);
        }
        return document;
    }

    private static List<String> validateRedirectUris(URI clientIdUri, Object value)
            throws ClientIdMetadataDocumentException {

        List<String> redirectUris = toStringList(value);
        if (redirectUris == null || redirectUris.isEmpty()) {
            throw new ClientIdMetadataDocumentException(INVALID_REDIRECT_URI);
        }
        for (String redirectUri : redirectUris) {
            URI uri;
            try {
                uri = new URI(redirectUri);
            } catch (URISyntaxException e) {
                throw new ClientIdMetadataDocumentException(INVALID_REDIRECT_URI, e);
            }
            if (uri.getRawFragment() != null || uri.getRawUserInfo() != null) {
                throw new ClientIdMetadataDocumentException(INVALID_REDIRECT_URI);
            }
            boolean sameOriginHttps = HTTPS.equals(uri.getScheme())
                    && clientIdUri.getHost().equalsIgnoreCase(uri.getHost()) && isDefaultHttpsPort(uri);
            boolean loopbackHttp = HTTP.equals(uri.getScheme())
                    && (IPV4_LOOPBACK.equals(uri.getHost()) || IPV6_LOOPBACK.equals(uri.getHost()));
            if (!sameOriginHttps && !loopbackHttp) {
                throw new ClientIdMetadataDocumentException(INVALID_REDIRECT_URI);
            }
            // Several URIs are stored as one regexp=, where IS cannot match [::1]: it is read as a character class.
            if (redirectUris.size() > 1 && IPV6_LOOPBACK.equals(uri.getHost())) {
                throw new ClientIdMetadataDocumentException(INVALID_REDIRECT_URI);
            }
        }
        return redirectUris;
    }

    private static String validateJwksUri(Map<String, Object> document) throws ClientIdMetadataDocumentException {

        Object jwksUri = document.get("jwks_uri");
        // The console stores a JWKS URI certificate only, so an inline jwks is not supported.
        if (!(jwksUri instanceof String) || document.containsKey("jwks")) {
            throw new ClientIdMetadataDocumentException(INVALID_CLIENT_AUTHENTICATION);
        }
        try {
            URI uri = new URI((String) jwksUri);
            if (!HTTPS.equals(uri.getScheme()) || !isDnsHost(uri.getHost()) || uri.getRawUserInfo() != null) {
                throw new ClientIdMetadataDocumentException(INVALID_CLIENT_AUTHENTICATION);
            }
        } catch (URISyntaxException e) {
            throw new ClientIdMetadataDocumentException(INVALID_CLIENT_AUTHENTICATION, e);
        }
        if (((String) jwksUri).length() > MAX_JWKS_URI_LENGTH) {
            throw new ClientIdMetadataDocumentException(VALUE_TOO_LONG);
        }
        return (String) jwksUri;
    }

    private static List<String> narrowGrantTypes(Object value) throws ClientIdMetadataDocumentException {

        List<String> declared = value == null ? Arrays.asList(GRANT_AUTHORIZATION_CODE) : toStringList(value);
        if (declared == null || !declared.contains(GRANT_AUTHORIZATION_CODE)) {
            throw new ClientIdMetadataDocumentException(INVALID_GRANT_TYPES);
        }
        List<String> grantTypes = new ArrayList<>();
        for (String grant : SUPPORTED_GRANTS) {
            if (declared.contains(grant)) {
                grantTypes.add(grant);
            }
        }
        return grantTypes;
    }

    /**
     * The name becomes the application name, so one IS would refuse falls back to the URL host.
     */
    private static String getClientName(Map<String, Object> document, URI clientIdUri) {

        Object value = document.get("client_name");
        String clientName = value instanceof String ? ((String) value).trim() : null;
        return StringUtils.isNotEmpty(clientName) && clientName.length() <= MAX_CLIENT_NAME_LENGTH
                && ApplicationMgtUtil.isRegexValidated(clientName) ? clientName : clientIdUri.getHost();
    }

    private static String getClientUri(Map<String, Object> document) {

        Object clientUri = document.get("client_uri");
        if (!(clientUri instanceof String) || ((String) clientUri).length() > MAX_CLIENT_URI_LENGTH) {
            return null;
        }
        try {
            return HTTPS.equals(new URI((String) clientUri).getScheme()) ? (String) clientUri : null;
        } catch (URISyntaxException e) {
            return null;
        }
    }

    /**
     * Build the callback value the console stores, to check its length: one URI as is, several as a
     * {@code regexp=} alternation with regex characters escaped. The {@code http://127.0.0.1} prefix stays literal,
     * because IS finds the loopback port to ignore by that text.
     */
    static String buildCallbackUrl(List<String> redirectUris) {

        if (redirectUris.size() == 1) {
            return redirectUris.get(0);
        }
        List<String> patterns = new ArrayList<>(redirectUris.size());
        for (String redirectUri : redirectUris) {
            patterns.add(redirectUri.startsWith(IPV4_LOOPBACK_PREFIX)
                    ? IPV4_LOOPBACK_PREFIX + escape(redirectUri.substring(IPV4_LOOPBACK_PREFIX.length()))
                    : escape(redirectUri));
        }
        return CALLBACK_URL_REGEXP_PREFIX + "(" + String.join("|", patterns) + ")";
    }

    private static String escape(String value) {

        return value.replaceAll(REGEX_SPECIAL_CHARACTERS, "\\\\$0");
    }

    private static List<String> toStringList(Object value) {

        if (!(value instanceof List)) {
            return null;
        }
        List<String> values = new ArrayList<>();
        for (Object item : (List<?>) value) {
            if (!(item instanceof String)) {
                return null;
            }
            values.add((String) item);
        }
        return values;
    }

    private static boolean isDnsHost(String host) {

        return StringUtils.isNotBlank(host) && !host.startsWith("[") && !InetAddressUtils.isIPv4Address(host);
    }

    private static boolean hasDotSegment(String path) {

        for (String segment : path.split("/", -1)) {
            if (".".equals(segment) || "..".equals(segment)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isDefaultHttpsPort(URI uri) {

        return uri.getPort() == -1 || uri.getPort() == HTTPS_PORT;
    }
}
