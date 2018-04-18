/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.oidc.session.backChannelLogout;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.event.IdentityEventConstants.EventName;
import org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * Handle OIDC logouts from backchannel.
 */
public class OIDCLogoutHandler extends AbstractEventHandler {

    private static Log log = LogFactory.getLog(OIDCLogoutHandler.class);

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        String opbsCookieValue = null;
        if (StringUtils.equals(event.getEventName(), EventName.SESSION_TERMINATE.name())) {
            HttpServletRequest request = getHttpRequestFromEvent(event);
            opbsCookieValue = getOIDCCookieFromRequest(request);

            if (StringUtils.isNotBlank(opbsCookieValue)) {
                LogoutRequestSender.getInstance().sendLogoutRequests(request);
                Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
                OIDCSessionManagementUtil.getSessionManager().removeOIDCSessionState(opBrowserStateCookie.getValue());

            } else {
                if (log.isDebugEnabled()) {
                    log.debug("There is no valid OIDC based service providers in the session.");
                }
            }
        }
    }

    @Override
    public String getName() {

        return "OIDCLogoutHandler";
    }

    private HttpServletRequest getHttpRequestFromEvent(Event event) {

        return (HttpServletRequest) event.getEventProperties().get(EventProperty.REQUEST);
    }

    private String getOIDCCookieFromRequest(HttpServletRequest request) {

        String opbsCookieValue = null;
        if (request != null) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (StringUtils.equals(cookie.getName(), OIDCSessionConstants.OPBS_COOKIE_ID)) {
                        opbsCookieValue = cookie.getValue();
                    }
                }
            }
        }
        return opbsCookieValue;
    }
}
