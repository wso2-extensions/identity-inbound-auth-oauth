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
import org.wso2.carbon.identity.event.IdentityEventConstants.EventName;
import org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.backchannellogout.LogoutRequestSender;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.RequestParams.TYPE;

/**
 * Event handler to support cross protocol logout.
 */
public class OIDCLogoutEventHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(OIDCLogoutEventHandler.class);
    private static final String COMMON_AUTH_CALLER_PATH = "commonAuthCallerPath";

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        if (log.isDebugEnabled()) {
            log.debug(event.getEventName() + " event received to OIDCLogoutEventHandler.");
        }

        if (isLogoutInitiatedFromOIDCApp(event)) {
            if (log.isDebugEnabled()) {
                log.debug("This is triggered from a OIDC service provider. Hence this request will not be handled "
                        + "by OIDCLogoutServlet");
            }
            return;
        }
        if (StringUtils.equals(event.getEventName(), EventName.SESSION_TERMINATE.name())) {
            String opbsCookieId = getopbsCookieId(event);
            if (StringUtils.isNotEmpty(opbsCookieId)) {
                if (log.isDebugEnabled()) {
                    log.debug("OPBS cookie with value " + opbsCookieId + " found. " +
                            "Initiating session termination.");
                }
                LogoutRequestSender.getInstance().sendLogoutRequests(opbsCookieId);
                OIDCSessionManagementUtil.getSessionManager().removeOIDCSessionState(opbsCookieId);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("There is no valid OIDC based service provider in the session to be terminated by " +
                            "the OIDCLogoutEventHandler.");
                }
            }
        }
    }

    @Override
    public String getName() {

        return "OIDCLogoutEventHandler";
    }

    private boolean isLogoutInitiatedFromOIDCApp(Event event) {

        HttpServletRequest request = getHttpRequestFromEvent(event);
        if (request != null) {
            if (StringUtils.equals(request.getParameter(TYPE), FrameworkConstants.RequestType.CLAIM_TYPE_OIDC)) {
                /* If a logout request is triggered from an OIDC app then the OIDCLogoutServlet
                and OIDCLogoutEventHandler both are triggered and the logout request is handled in both
                places. https://github.com/wso2/product-is/issues/6418
                */
                return true;
            }
        }
        return false;
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
            if (log.isDebugEnabled()) {
                log.debug("HttpServletRequest object is not found in the event. Hence getting opbs cookie from the " +
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
     * @return opbscookie value
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
     * @param event Event
     * @return opbs cookie value
     */
    private String getOpbsCookieFromContext(Event event) {

        if (event.getEventProperties().get(EventProperty.SESSION_CONTEXT) != null) {
            SessionContext sessionContext =
                    (SessionContext) event.getEventProperties().get(EventProperty.SESSION_CONTEXT);
            return (String) sessionContext.getProperty(OIDCSessionConstants.OPBS_COOKIE_ID);
        }
        if (log.isDebugEnabled()) {
            log.debug("Since the session context is not found in the event, Could not get the opbs cookie value");
        }
        return null;
    }

    private HttpServletRequest getHttpRequestFromEvent(Event event) {

        return (HttpServletRequest) event.getEventProperties().get(EventProperty.REQUEST);
    }

    private boolean hasOPBSCookieValue(Cookie opbsCookie) {

        String opbsCookieValue = null;

        if (opbsCookie != null) {
            opbsCookieValue = opbsCookie.getValue();
        }

        return StringUtils.isNotBlank(opbsCookieValue);
    }
}
