/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.oidc.session.backchannellogout;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * Used to send logout request.
 */
public class LogoutRequestSender {

    private static final Log LOG = LogFactory.getLog(LogoutRequestSender.class);
    private static LogoutRequestSender instance = null;

    private static ExecutorService threadPool = null;
    private boolean hostNameVerificationEnabled = true;
    private static int httpConnectTimeout = 0;
    private static int httpSocketTimeout = 0;
    private static final String LOGOUT_TOKEN = "logout_token";

    private LogoutRequestSender() {

        String poolSize = IdentityUtil.getProperty(OIDCSessionConstants.OIDCLogoutRequestConstants.POOL_SIZE);
        String workQueueSize = IdentityUtil.getProperty(
                OIDCSessionConstants.OIDCLogoutRequestConstants.WORK_QUEUE_SIZE);
        String keepAliveTime = IdentityUtil.getProperty(
                OIDCSessionConstants.OIDCLogoutRequestConstants.KEEP_ALIVE_TIME);
        String httpConnectTimeoutProperty = IdentityUtil.getProperty(
                OIDCSessionConstants.OIDCLogoutRequestConstants.HTTP_CONNECT_TIMEOUT);
        String httpSocketTimeoutProperty = IdentityUtil.getProperty(
                OIDCSessionConstants.OIDCLogoutRequestConstants.HTTP_SOCKET_TIMEOUT);
        String hostNameVerificationEnabledProperty = IdentityUtil.getProperty(
                IdentityConstants.ServerConfig.SLO_HOST_NAME_VERIFICATION_ENABLED);

        if (StringUtils.isBlank(poolSize)) {
            poolSize = OIDCSessionConstants.OIDCLogoutRequestConstants.DEFAULT_POOL_SIZE;
        }
        if (StringUtils.isBlank(workQueueSize)) {
            workQueueSize = OIDCSessionConstants.OIDCLogoutRequestConstants.DEFAULT_WORK_QUEUE_SIZE;
        }
        if (StringUtils.isBlank(keepAliveTime)) {
            keepAliveTime = OIDCSessionConstants.OIDCLogoutRequestConstants.DEFAULT_KEEP_ALIVE_TIME;
        }
        if (StringUtils.isBlank(httpConnectTimeoutProperty)) {
            httpConnectTimeoutProperty = OIDCSessionConstants.OIDCLogoutRequestConstants.DEFAULT_HTTP_CONNECT_TIMEOUT;
        }
        if (StringUtils.isBlank(httpSocketTimeoutProperty)) {
            httpSocketTimeoutProperty = OIDCSessionConstants.OIDCLogoutRequestConstants.DEFAULT_HTTP_SOCKET_TIMEOUT;
        }

        int poolSizeInt = Integer.parseInt(poolSize);
        int workQueueSizeInt = Integer.parseInt(workQueueSize);
        int keepAliveTimeLong = Integer.parseInt(keepAliveTime);

        if (poolSizeInt <= 0) {
            poolSizeInt = Integer.parseInt(OIDCSessionConstants.OIDCLogoutRequestConstants.DEFAULT_POOL_SIZE);
        }

        BlockingQueue<Runnable> workQueue = null;
        if (workQueueSizeInt > 0) {
            workQueue = new ArrayBlockingQueue<Runnable>(workQueueSizeInt);
        } else if (workQueueSizeInt == -1) {
            LOG.warn("Work queue size is set to -1. Using unbounded work queue.");
            workQueue = new LinkedBlockingQueue<Runnable>();
        } else {
            workQueueSizeInt = Integer.parseInt(
                    OIDCSessionConstants.OIDCLogoutRequestConstants.DEFAULT_WORK_QUEUE_SIZE);
            workQueue = new ArrayBlockingQueue<Runnable>(workQueueSizeInt);
        }

        threadPool = new ThreadPoolExecutor(poolSizeInt, poolSizeInt, keepAliveTimeLong,
                TimeUnit.MILLISECONDS, workQueue);

        httpConnectTimeout = Integer.parseInt(httpConnectTimeoutProperty);
        httpSocketTimeout = Integer.parseInt(httpSocketTimeoutProperty);
        if ("false".equalsIgnoreCase(hostNameVerificationEnabledProperty)) {
            hostNameVerificationEnabled = false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("LogoutRequestSender thread pool initialized with pool size: " + poolSizeInt +
                    ", work queue size: " + workQueueSizeInt + ", keep alive time: " + keepAliveTimeLong +
                    ". Request parameters: httpConnectTimeout: " + httpConnectTimeout +
                    ", httpSocketTimeout: " + httpSocketTimeout +
                    ", hostNameVerificationEnabled: " + hostNameVerificationEnabled);
        }
    }

    /**
     * getInstance() method of LogoutRequestSender, as it is a singleton.
     *
     * @return LogoutRequestSender instance
     */
    public static LogoutRequestSender getInstance() {

        if (instance == null) {
            synchronized (LogoutRequestSender.class) {
                if (instance == null) {
                    instance = new LogoutRequestSender();
                }
            }
        }

        return instance;
    }

    /**
     * Sends logout requests to all service providers.
     *
     * @param request
     *
     * @deprecated This method was deprecated to move OIDC SessionParticipantCache to the tenant space.
     * Use {@link #sendLogoutRequests(String, String)} instead.
     */
    @Deprecated
    public void sendLogoutRequests(HttpServletRequest request) {

        Cookie opbsCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
        if (opbsCookie != null) {
            sendLogoutRequests(opbsCookie.getValue());
        } else {
            LOG.error("No opbscookie exists in the request");
        }
    }

    /**
     * Sends logout requests to all service providers.
     *
     * @param opbsCookieId
     *
     * @deprecated This method was deprecated to move OIDCSessionParticipantCache to the tenant space.
     * Use {@link #sendLogoutRequests(String, String)} instead.
     */
    @Deprecated
    public void sendLogoutRequests(String opbsCookieId) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was added as the cache maintained tenant.
        sendLogoutRequests(opbsCookieId, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Sends logout requests to all service providers.
     *
     * @param opbsCookieId OPBS Cookie ID value
     * @param tenantDomain Tenant Domain
     */
    public void sendLogoutRequests(String opbsCookieId, String tenantDomain) {

        Map<String, String> logoutTokenList = getLogoutTokenList(opbsCookieId, tenantDomain);
        if (MapUtils.isNotEmpty(logoutTokenList)) {
            // For each logoutReq, create a new task and submit it to the thread pool.
            for (Map.Entry<String, String> logoutTokenMap : logoutTokenList.entrySet()) {
                String logoutToken = logoutTokenMap.getKey();
                String bcLogoutUrl = logoutTokenMap.getValue();
                LOG.debug("A LogoutReqSenderTask will be assigned to the thread pool.");
                threadPool.submit(new LogoutReqSenderTask(logoutToken, bcLogoutUrl));
            }
        }
    }

    /**
     * Returns a Map with logout tokens and back-channel logut Url of Service providers.
     *
     * @param opbsCookie OpbsCookie.
     * @return Map with logoutToken, back-channel logout Url.
     */
    private Map<String, String> getLogoutTokenList(String opbsCookie, String tenantDomain) {

        Map<String, String> logoutTokenList = null;
        try {
            DefaultLogoutTokenBuilder logoutTokenBuilder = new DefaultLogoutTokenBuilder();
            logoutTokenList = logoutTokenBuilder.buildLogoutToken(opbsCookie, tenantDomain);
        } catch (IdentityOAuth2Exception e) {
            LOG.error("Error while initializing " + DefaultLogoutTokenBuilder.class, e);
        } catch (InvalidOAuthClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error while obtaining logout token list for the obpsCookie: " + opbsCookie +
                                "& tenant domain: " + tenantDomain, e);
            }
        }
        return logoutTokenList;
    }

    /**
     * This class is used to model a single logout request that is being sent to a session participant.
     * It will send the logout req. to the session participant in its 'run' method when this job is
     * submitted to the thread pool.
     */
    private class LogoutReqSenderTask implements Runnable {

        private String logoutToken;
        private String backChannelLogouturl;

        public LogoutReqSenderTask(String logoutToken, String backChannelLogouturl) {

            this.logoutToken = logoutToken;
            this.backChannelLogouturl = backChannelLogouturl;
        }

        @Override
        public void run() {

            if (LOG.isDebugEnabled()) {
                LOG.debug("Starting backchannel logout request to: " + backChannelLogouturl);
            }

            List<NameValuePair> logoutReqParams = new ArrayList<NameValuePair>();
            CloseableHttpClient httpClient = null;
            try {
                if (!hostNameVerificationEnabled) {
                    httpClient = HttpClients.custom()
                            .setHostnameVerifier(SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER)
                            .build();
                } else {
                    httpClient = HttpClients.createDefault();
                }
                logoutReqParams.add(new BasicNameValuePair(LOGOUT_TOKEN, logoutToken));

                HttpPost httpPost = new HttpPost(backChannelLogouturl);
                try {
                    httpPost.setEntity(new UrlEncodedFormEntity(logoutReqParams));
                } catch (UnsupportedEncodingException e) {
                    LOG.error("Error while encoding logout request parameters.", e);
                }
                RequestConfig requestConfig = RequestConfig.custom().setConnectTimeout(httpConnectTimeout)
                        .setSocketTimeout(httpSocketTimeout).build();
                httpPost.setConfig(requestConfig);

                HttpResponse response = httpClient.execute(httpPost);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Backchannel logout response: " + response.getStatusLine());
                }
            } catch (SocketTimeoutException e) {
                LOG.error("Timeout occurred while sending logout requests to: " + backChannelLogouturl);
            } catch (IOException e) {
                LOG.error("Error sending logout requests to: " + backChannelLogouturl, e);
            } finally {
                if (httpClient != null) {
                    try {
                        httpClient.close();
                    } catch (IOException e) {
                        LOG.error("Error closing http client.", e);
                    }
                }
            }
        }
    }
}
