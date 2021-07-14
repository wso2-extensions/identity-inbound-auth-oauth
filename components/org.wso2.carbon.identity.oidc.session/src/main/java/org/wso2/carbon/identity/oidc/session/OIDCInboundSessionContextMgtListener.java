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

package org.wso2.carbon.identity.oidc.session;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.listener.SessionContextMgtListener;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Session Context context listener implementation for the OIDC.
 */
public class OIDCInboundSessionContextMgtListener implements SessionContextMgtListener {

    private static final Log log = LogFactory.getLog(OIDCInboundSessionContextMgtListener.class);
    private static final String INBOUND_TYPE = "oidc";

    @Override
    public String getInboundType() {

        return INBOUND_TYPE;
    }

    @Override
    public Map<String, String> onPreCreateSession(String sessionId, HttpServletRequest httpServletRequest,
                                                  HttpServletResponse httpServletResponse,
                                                  AuthenticationContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Handling onPreCreateSession for oidc.");
        }
        Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(httpServletRequest);
        String clientId = context.getAuthenticationRequest().getRelyingParty();
        String obpsValue;
        // Successful user authentication.
        if (opBrowserStateCookie == null) {
            // New browser session.
            if (log.isDebugEnabled()) {
                log.debug("User authenticated. Initiate OIDC browser session.");
            }
            // Create a new opbs cookie value and add to session context.
            obpsValue = OIDCSessionManagementUtil.generateOPBrowserStateCookieValue(context.getLoginTenantDomain());
        } else {
            // Browser session exists.
            OIDCSessionState previousSessionState =
                    OIDCSessionManagementUtil.getSessionManager().getOIDCSessionState(opBrowserStateCookie.getValue());
            if (previousSessionState != null) {
                if (!previousSessionState.getSessionParticipants().contains(clientId)) {
                    // User is authenticated to a new client. Restore browser session state.
                    if (log.isDebugEnabled()) {
                        log.debug("User is authenticated to a new client. Restore browser session state.");
                    }
                    // Create a new opbs cookie value and add to session context.
                    obpsValue = OIDCSessionManagementUtil
                            .generateOPBrowserStateCookieValue(context.getLoginTenantDomain());
                } else {
                    // Store current opbs cookie value to session context.
                    obpsValue = opBrowserStateCookie.getValue();
                }
            } else {
                    log.warn("No session state found for the received Session ID : "
                            + opBrowserStateCookie.getValue());
                    if (log.isDebugEnabled()) {
                        log.debug("Restore browser session state.");
                    }
                // Create a new opbs cookie value and add to session context.
                obpsValue = OIDCSessionManagementUtil.generateOPBrowserStateCookieValue(context.getLoginTenantDomain());
            }
        }
        Map<String, String> map = new HashMap<>();
        map.put(OIDCSessionConstants.OPBS_COOKIE_ID, obpsValue);
        return map;
    }

    @Override
    public Map<String, String> onPreUpdateSession(String sessionId, HttpServletRequest httpServletRequest,
                                               HttpServletResponse httpServletResponse,
                                               AuthenticationContext authenticationContext) {

        if (log.isDebugEnabled()) {
            log.debug("Handling onPreUpdateSession for oidc.");
        }
        return this.onPreCreateSession(sessionId, httpServletRequest, httpServletResponse, authenticationContext);
    }
}
