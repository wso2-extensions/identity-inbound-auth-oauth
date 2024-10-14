/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.util;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.security.KeystoreUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLContext;
/**
 * HTTP Client related util class.
 */
public class HttpClientUtil {

    private static final Log log = LogFactory.getLog(HttpClientUtil.class);
    public static final String HOST_NAME_VERIFIER = "httpclient.hostnameVerifier";
    public static final String STRICT = "Strict";
    public static final String ALLOW_ALL = "AllowAll";

    /**
     * Return a http client instance.
     *
     * @param configUrl Server url.
     * @return
     */
    public static HttpClient getHttpClient(URL configUrl) throws MalformedURLException {

        int port = configUrl.getPort();
        String protocol = configUrl.getProtocol();
        return getHttpClient(port, protocol);
    }

    /**
     * Return a http client instance.
     *
     * @param port     Server port.
     * @param protocol Service endpoint protocol http/https.
     * @return
     */
    public static HttpClient getHttpClient(int port, String protocol) {

        String proxyEnabled = IdentityUtil.getProperty(Constants.PROXY_ENABLE);
        String proxyHost = IdentityUtil.getProperty(Constants.PROXY_HOST);
        String proxyPort = IdentityUtil.getProperty(Constants.PROXY_PORT);
        String proxyUsername = IdentityUtil.getProperty(Constants.PROXY_USERNAME);
        String proxyPassword = IdentityUtil.getProperty(Constants.PROXY_PASSWORD);

        PoolingHttpClientConnectionManager pool = null;
        try {
            pool = getPoolingHttpClientConnectionManager(protocol);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error while getting http client connection manager. ", e);
        }

        RequestConfig params = RequestConfig.custom().build();
        HttpClientBuilder clientBuilder = HttpClients.custom().setConnectionManager(pool)
                .setDefaultRequestConfig(params);

        if (Boolean.parseBoolean(proxyEnabled)) {
            HttpHost host = new HttpHost(proxyHost, Integer.parseInt(proxyPort), protocol);
            DefaultProxyRoutePlanner routePlanner;
            routePlanner = new DefaultProxyRoutePlanner(host);
            clientBuilder = clientBuilder.setRoutePlanner(routePlanner);
            if (!StringUtils.isBlank(proxyUsername) && !StringUtils.isBlank(proxyPassword)) {
                CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
                credentialsProvider.setCredentials(new AuthScope(proxyHost, Integer.parseInt(proxyPort)),
                        new UsernamePasswordCredentials(proxyUsername, proxyPassword));
                clientBuilder = clientBuilder.setDefaultCredentialsProvider(credentialsProvider);
            }
        }
        return clientBuilder.build();
    }

    /**
     * Return a PoolingHttpClientConnectionManager instance.
     *
     * @param protocol Service endpoint protocol. It can be http/https.
     * @return PoolManager.
     */
    private static PoolingHttpClientConnectionManager getPoolingHttpClientConnectionManager(String protocol)
            throws IdentityOAuth2Exception {

        PoolingHttpClientConnectionManager poolManager;
        if (Constants.PROTOCOL_HTTPS.equals(protocol)) {
            SSLConnectionSocketFactory socketFactory = createSocketFactory();
            org.apache.http.config.Registry<ConnectionSocketFactory> socketFactoryRegistry =
                    RegistryBuilder.<ConnectionSocketFactory>create()
                            .register(Constants.PROTOCOL_HTTPS, socketFactory).build();
            poolManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
        } else {
            poolManager = new PoolingHttpClientConnectionManager();
        }
        return poolManager;
    }

    private static SSLConnectionSocketFactory createSocketFactory() throws IdentityOAuth2Exception {

        SSLContext sslContext;
        String keyStorePath = CarbonUtils.getServerConfiguration()
                .getFirstProperty(Constants.TRUSTSTORE_LOCATION);
        String keyStorePassword = CarbonUtils.getServerConfiguration()
                .getFirstProperty(Constants.TRUSTSTORE_PASSWORD);
        try {
            KeyStore trustStore = KeystoreUtils.getKeystoreInstance(Constants.TRUSTSTORE_TYPE);
            trustStore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());
            sslContext = SSLContexts.custom().loadTrustMaterial(trustStore).build();

            X509HostnameVerifier hostnameVerifier;
            String hostnameVerifierOption = System.getProperty(HOST_NAME_VERIFIER);

            if (ALLOW_ALL.equalsIgnoreCase(hostnameVerifierOption)) {
                hostnameVerifier = SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
            } else if (STRICT.equalsIgnoreCase(hostnameVerifierOption)) {
                hostnameVerifier = SSLSocketFactory.STRICT_HOSTNAME_VERIFIER;
            } else {
                hostnameVerifier = SSLSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER;
            }

            return new SSLConnectionSocketFactory(sslContext, hostnameVerifier);
        } catch (KeyStoreException | NoSuchProviderException e) {
            throw new IdentityOAuth2Exception("Failed to read from Key Store. ", e);
        } catch (IOException e) {
            throw new IdentityOAuth2Exception("Key Store not found in " + keyStorePath, e);
        } catch (CertificateException e) {
            throw new IdentityOAuth2Exception("Failed to read Certificate. ", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IdentityOAuth2Exception("Failed to load Key Store from " + keyStorePath, e);
        } catch (KeyManagementException e) {
            throw new IdentityOAuth2Exception("Failed to load key from " + keyStorePath, e);
        }
    }

}
