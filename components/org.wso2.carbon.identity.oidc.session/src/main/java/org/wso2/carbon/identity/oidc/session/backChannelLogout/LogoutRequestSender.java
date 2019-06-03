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
package org.wso2.carbon.identity.oidc.session.backChannelLogout;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class LogoutRequestSender {

    private static Log log = LogFactory.getLog(LogoutRequestSender.class);
    private static ExecutorService threadPool = Executors.newFixedThreadPool(2);
    private static LogoutRequestSender instance = new LogoutRequestSender();
    private static final String LOGOUT_TOKEN = "logout_token";

    private LogoutRequestSender() {

    }

    /**
     * getInstance() method of LogoutRequestSender, as it is a singleton
     *
     * @return LogoutRequestSender instance
     */
    public static LogoutRequestSender getInstance() {

        return instance;
    }

    /**
     * Sends logout requests to all service providers.
     *
     * @param request
     */
    public void sendLogoutRequests(HttpServletRequest request) {

        Map<String, String> logoutTokenList = getLogoutTokenList(request);
        if (MapUtils.isNotEmpty(logoutTokenList)) {
            // For each logoutReq, create a new task and submit it to the thread pool.
            for (Map.Entry<String, String> logoutTokenMap : logoutTokenList.entrySet()) {
                String logoutToken = logoutTokenMap.getKey();
                String bcLogoutUrl = logoutTokenMap.getValue();
                threadPool.submit(new LogoutReqSenderTask(logoutToken, bcLogoutUrl));
                if (log.isDebugEnabled()) {
                    log.debug("A logoutReqSenderTask is assigned to the thread pool");

                }
            }
        }
    }

    /**
     * Returns a Map with logout tokens and back-channel logut Url of Service providers.
     *
     * @param request
     * @return Map with logoutToken, back-channel logout Url.
     */
    private Map<String, String> getLogoutTokenList(HttpServletRequest request) {

        Map<String, String> logoutTokenList = null;
        try {
            DefaultLogoutTokenBuilder logoutTokenBuilder = new DefaultLogoutTokenBuilder();
            logoutTokenList = logoutTokenBuilder.buildLogoutToken(request);
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            log.error("Error while initializing " + DefaultLogoutTokenBuilder.class, e);
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
            if (log.isDebugEnabled()) {
                log.debug("Starting backchannel logout request to: " + backChannelLogouturl);
            }

            List<NameValuePair> logoutReqParams = new ArrayList<NameValuePair>();
            String hostNameVerificationEnabledProperty =
                    IdentityUtil.getProperty(IdentityConstants.ServerConfig.SLO_HOST_NAME_VERIFICATION_ENABLED);
            boolean isHostNameVerificationEnabled = true;
            if ("false".equalsIgnoreCase(hostNameVerificationEnabledProperty)) {
                isHostNameVerificationEnabled = false;
            }
            try {
                HttpClient httpClient;
                if (!isHostNameVerificationEnabled) {
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
                    log.error("Error while sending logout token", e);
                }
                HttpResponse response = httpClient.execute(httpPost);
                if (log.isDebugEnabled()) {
                    log.debug("Backchannel logout response: " + response.getStatusLine());
                }

            } catch (IOException e) {
                log.error("Error sending logout requests to: " + backChannelLogouturl, e);
            }
        }
    }
}
