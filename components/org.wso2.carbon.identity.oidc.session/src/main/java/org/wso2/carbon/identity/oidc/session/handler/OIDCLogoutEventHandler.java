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
import org.wso2.carbon.identity.event.IdentityEventConstants.EventName;
import org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.oidc.session.backChannelLogout.LogoutRequestSender;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * Event handler to support cross protocol logout.
 */
public class OIDCLogoutEventHandler extends AbstractEventHandler {

    private static Log log = LogFactory.getLog(OIDCLogoutEventHandler.class);

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        if (log.isDebugEnabled()) {
            log.debug(event.getEventName() + " event received to OIDCLogoutEventHandler.");
        }

        if (StringUtils.equals(event.getEventName(), EventName.SESSION_TERMINATE.name())) {
            HttpServletRequest request = getHttpRequestFromEvent(event);
            Cookie opbsCookie = null;

            if (request != null) {
                opbsCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
            }

            if (hasOPBSCookieValue(opbsCookie)) {
                if (log.isDebugEnabled()) {
                    log.debug("OPBS cookie with value " + opbsCookie.getValue() + " found. " +
                            "Initiating session termination.");
                }
                LogoutRequestSender.getInstance().sendLogoutRequests(request);
                OIDCSessionManagementUtil.getSessionManager().removeOIDCSessionState(opbsCookie.getValue());
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

    private HttpServletRequest getHttpRequestFromEvent(Event event) {

        return (HttpServletRequest) event.getEventProperties().get(EventProperty.REQUEST);
    }

    private boolean hasOPBSCookieValue (Cookie opbsCookie) {

        String opbsCookieValue = null;

        if (opbsCookie != null) {
            opbsCookieValue = opbsCookie.getValue();
        }

        return StringUtils.isNotBlank(opbsCookieValue);
    }
}
