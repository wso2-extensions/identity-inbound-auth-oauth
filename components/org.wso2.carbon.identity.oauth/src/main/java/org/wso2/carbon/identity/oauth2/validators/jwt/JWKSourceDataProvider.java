/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.validators.jwt;

import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.cache.JWKSCache;
import org.wso2.carbon.identity.oauth2.cache.JWKSCacheEntry;
import org.wso2.carbon.identity.oauth2.cache.JWKSCacheKey;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * Provides JWK sources for JWT validation.
 */
public class JWKSourceDataProvider {

    private static final int DEFAULT_HTTP_CONNECTION_TIMEOUT = 1000;
    private static final int DEFAULT_HTTP_READ_TIMEOUT = 1000;
    private static final String HTTP_CONNECTION_TIMEOUT_XPATH = "JWTValidatorConfigs.JWKSEndpoint" +
            ".HTTPConnectionTimeout";
    private static final String HTTP_READ_TIMEOUT_XPATH = "JWTValidatorConfigs.JWKSEndpoint" +
            ".HTTPReadTimeout";
    private static final String HTTP_SIZE_LIMIT_XPATH = "JWTValidatorConfigs.JWKSEndpoint" +
            ".HTTPSizeLimit";
    private static final Log log = LogFactory.getLog(JWKSourceDataProvider.class);

    private static JWKSourceDataProvider jwkSourceDataProvider = new JWKSourceDataProvider();

    private JWKSourceDataProvider() {

    }

    /**
     * Returns an instance of JWK-Source data holder.
     *
     * @return JWKSSourceDataHolder.
     */
    public static JWKSourceDataProvider getInstance() {

        return jwkSourceDataProvider;
    }

    /**
     * Get cached JWKSet for the jwks_uri.
     *
     * @param jwksUri Identity provider's JWKS endpoint.
     * @return RemoteJWKSet.
     * @throws MalformedURLException for invalid URL.
     */
    public RemoteJWKSet<SecurityContext> getJWKSource(String jwksUri) throws MalformedURLException {

        JWKSCacheKey jwksCacheKey = new JWKSCacheKey(jwksUri);
        JWKSCacheEntry jwksCacheEntry = JWKSCache.getInstance().getValueFromCache(jwksCacheKey);
        RemoteJWKSet<SecurityContext> jwkSet = null;
        if (jwksCacheEntry != null) {
            jwkSet = jwksCacheEntry.getValue();
            if (log.isDebugEnabled()) {
                log.debug("Retrieving JWKS for " + jwksUri + " from cache.");
            }
        }
        if (jwkSet == null) {
            jwkSet = retrieveJWKSFromJWKSEndpoint(jwksUri);
            JWKSCache.getInstance().addToCache(jwksCacheKey, new JWKSCacheEntry(jwkSet));
            if (log.isDebugEnabled()) {
                log.debug("Fetching JWKS from remote endpoint.");
            }
        }
        return jwkSet;
    }

    /**
     * Retrieve the new-keyset from the JWKS endpoint in case of signature validation failure.
     *
     * @param jwksUri Identity providers jwks_uri.
     * @throws IdentityOAuth2Exception for invalid/malformed URL.
     */
    public void refreshJWKSResource(String jwksUri) throws IdentityOAuth2Exception {

        try {
            JWKSCacheKey jwksCacheKey = new JWKSCacheKey(jwksUri);
            JWKSCache.getInstance().clearCacheEntry(jwksCacheKey);
            RemoteJWKSet<SecurityContext> jwkSet = retrieveJWKSFromJWKSEndpoint(jwksUri);
            JWKSCache.getInstance().addToCache(jwksCacheKey, new JWKSCacheEntry(jwkSet));
        } catch (MalformedURLException e) {
            throw new IdentityOAuth2Exception("Provided URI is malformed. jwks_uri: " + jwksUri, e);
        }
    }

    /**
     * Retrieve JWKS from jwks_uri.
     *
     * @param jwksUri Identity provider's jwks_uri.
     * @return RemoteJWKSet
     * @throws MalformedURLException for invalid URL.
     */
    private RemoteJWKSet<SecurityContext> retrieveJWKSFromJWKSEndpoint(String jwksUri) throws MalformedURLException {

        // Retrieve HTTP endpoint configurations.
        int connectionTimeout = readHTTPConnectionConfigValue(HTTP_CONNECTION_TIMEOUT_XPATH);
        int readTimeout = readHTTPConnectionConfigValue(HTTP_READ_TIMEOUT_XPATH);
        int sizeLimit = readHTTPConnectionConfigValue(HTTP_SIZE_LIMIT_XPATH);

        if (connectionTimeout <= 0) {
            connectionTimeout = DEFAULT_HTTP_CONNECTION_TIMEOUT;
        }
        if (readTimeout <= 0) {
            readTimeout = DEFAULT_HTTP_READ_TIMEOUT;
        }
        if (sizeLimit <= 0) {
            sizeLimit = RemoteJWKSet.DEFAULT_HTTP_SIZE_LIMIT;
        }
        DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(
                connectionTimeout,
                readTimeout,
                sizeLimit);

        return new RemoteJWKSet<>(new URL(jwksUri), resourceRetriever);
    }

    /**
     * Read HTTP connection configurations from identity.xml file.
     *
     * @param xPath xpath of the config property.
     * @return Config property value.
     */
    private int readHTTPConnectionConfigValue(String xPath) {

        int configValue = 0;
        String config = IdentityUtil.getProperty(xPath);
        if (StringUtils.isNotBlank(config)) {
            try {
                configValue = Integer.parseInt(config);
            } catch (NumberFormatException e) {
                log.error("Provided HTTP connection config value in " + xPath + " should be an integer type. Value : "
                        + config);
            }
        }
        return configValue;
    }
}
