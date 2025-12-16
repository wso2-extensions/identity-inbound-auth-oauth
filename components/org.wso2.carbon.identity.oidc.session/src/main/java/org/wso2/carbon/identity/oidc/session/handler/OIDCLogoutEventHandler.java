/*
 *  Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oidc.session.handler;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.event.IdentityEventConstants.EventName;
import org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.backchannellogout.LogoutRequestSender;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.RequestParams.TYPE;

/**
 * This class handles logout events for OpenID Connect (OIDC) sessions in WSO2 Identity Server.
 * The handler performs necessary session termination tasks, including retrieving the OPBS
 * (OpenID Provider Browser State) cookie and removing the associated session state.
 *
 */
public class OIDCLogoutEventHandler extends AbstractEventHandler {

    private static final Log LOG = LogFactory.getLog(OIDCLogoutEventHandler.class);
    private static final String OIDC_LOGOUT_EVENT_HANDLER = "OIDCLogoutEventHandler";

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        if (LOG.isDebugEnabled()) {
            LOG.debug(event.getEventName() + " event received to " + OIDC_LOGOUT_EVENT_HANDLER);
        }

        if (isLogoutInitiatedFromOIDCApp(event)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("This is triggered from a OIDC service provider. Hence this request will not be handled "
                        + "by OIDCLogoutServlet");
            }
            return;
        }
        if (StringUtils.equals(event.getEventName(), EventName.SESSION_TERMINATE.name())) {
            Object context = event.getEventProperties().get(EventProperty.CONTEXT);
            if (context != null) {
                return;
            }
            String opbsCookieId = getopbsCookieId(event);
            if (StringUtils.isNotEmpty(opbsCookieId)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("OPBS cookie with value " + opbsCookieId + " found. " +
                            "Initiating session termination.");
                }
                HttpServletRequest request = getHttpRequestFromEvent(event);
                String tenantDomain;
                if (request != null) {
                    tenantDomain = OAuth2Util.resolveTenantDomain(request);
                } else {
                    tenantDomain = getTenantDomainFromContext(event);
                }
                LogoutRequestSender.getInstance().sendLogoutRequests(opbsCookieId, tenantDomain);
                OIDCSessionManagementUtil.getSessionManager().removeOIDCSessionState(opbsCookieId, tenantDomain);
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("There is no valid OIDC based service provider in the session to be terminated by " +
                            "the OIDCLogoutEventHandler.");
                }
            }
        }
    }

    @Override
    public String getName() {

        return OIDC_LOGOUT_EVENT_HANDLER;
    }

    private boolean isLogoutInitiatedFromOIDCApp(Event event) {

        HttpServletRequest request = getHttpRequestFromEvent(event);
        /* If a logout request is triggered from an OIDC app then the OIDCLogoutServlet
        and OIDCLogoutEventHandler both are triggered and the logout request is handled in both
        places. https://github.com/wso2/product-is/issues/6418
        */
        return request != null && FrameworkConstants.RequestType.CLAIM_TYPE_OIDC.equals(request.getParameter(TYPE));
    }

    private String getopbsCookieId(Event event) {

        HttpServletRequest request = getHttpRequestFromEvent(event);
        String opbsCookie = null;
        if (request != null) {
            // Get the opbscookie from request.
            opbsCookie = getOpbsCookieFromRequest(request);
        }
        if (StringUtils.isBlank(opbsCookie)) {
            // If opbscookie is not found in the request, get from session context.
            if (LOG.isDebugEnabled()) {
                LOG.debug("HttpServletRequest object is not found in the event. Hence getting opbs cookie from the " +
                        "session context.");
            }
            opbsCookie = getOpbsCookieFromContext(event);
        }
        return opbsCookie;
    }

    /**
     * Get opbscookie value from the httpservlet request.
     *
     * @param request HttpServletRequest
     * @return opbscookie value.
     */
    private String getOpbsCookieFromRequest(HttpServletRequest request) {

        Cookie opbsCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
        if (opbsCookie != null) {
            return opbsCookie.getValue();
        }
        return null;
    }

    /**
     * Get opbs cookie value from session context.
     *
     * @param event Event.
     * @return opbs cookie value.
     */
    private String getOpbsCookieFromContext(Event event) {

        if (event.getEventProperties().get(EventProperty.SESSION_CONTEXT) != null) {
            SessionContext sessionContext =
                    (SessionContext) event.getEventProperties().get(EventProperty.SESSION_CONTEXT);
            return (String) sessionContext.getProperty(OIDCSessionConstants.OPBS_COOKIE_ID);
        }
        LOG.debug("Since the session context is not found in the event, Could not get the opbs cookie value");
        return null;
    }

    /**
     * Get the tenant domain from the session context.
     *
     * @param event Event.
     * @return Tenant domain.
     */
    private String getTenantDomainFromContext(Event event) {

        if (event.getEventProperties().get(EventProperty.SESSION_CONTEXT) != null) {
            SessionContext sessionContext =
                    (SessionContext) event.getEventProperties().get(EventProperty.SESSION_CONTEXT);
            return (String) sessionContext.getProperty(FrameworkUtils.TENANT_DOMAIN);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Since the session context is not found in the event, Could not get the tenant domain from " +
                    "session context.");
        }
        return null;
    }

    private HttpServletRequest getHttpRequestFromEvent(Event event) {

        return (HttpServletRequest) event.getEventProperties().get(EventProperty.REQUEST);
    }
}
