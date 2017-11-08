/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oidc.session.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.equinox.http.helper.ContextPathServletAdaptor;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.oidc.session.ClaimAdderImp;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.servlet.OIDCLogoutServlet;
import org.wso2.carbon.identity.oidc.session.servlet.OIDCSessionIFrameServlet;
import org.wso2.carbon.identity.openidconnect.ClaimAdder;
import org.wso2.carbon.user.core.service.RealmService;

import javax.servlet.Servlet;

@Component(
        name = "identity.oidc.session.component",
        immediate = true
)
public class OIDCSessionManagementComponent {
    private static final Log log = LogFactory.getLog(OIDCSessionManagementComponent.class);

    protected void activate(ComponentContext context) {

        HttpService httpService = OIDCSessionManagementComponentServiceHolder.getHttpService();

        // Register Session IFrame Servlet
        Servlet sessionIFrameServlet = new ContextPathServletAdaptor(new OIDCSessionIFrameServlet(),
                OIDCSessionConstants.OIDCEndpoints.OIDC_SESSION_IFRAME_ENDPOINT);
        try {
            httpService.registerServlet(OIDCSessionConstants.OIDCEndpoints.OIDC_SESSION_IFRAME_ENDPOINT,
                    sessionIFrameServlet, null, null);
        } catch (Exception e) {
            String msg = "Error when registering OIDC Session IFrame Servlet via the HttpService.";
            log.error(msg, e);
            throw new RuntimeException(msg, e);
        }

        Servlet logoutServlet = new ContextPathServletAdaptor(new OIDCLogoutServlet(),
                OIDCSessionConstants.OIDCEndpoints.OIDC_LOGOUT_ENDPOINT);
        try {
            httpService.registerServlet(OIDCSessionConstants.OIDCEndpoints.OIDC_LOGOUT_ENDPOINT, logoutServlet, null,
                    null);
        } catch (Exception e) {
            String msg = "Error when registering OIDC Logout Servlet via the HttpService.";
            log.error(msg, e);
            throw new RuntimeException(msg, e);
        }
        if (log.isDebugEnabled()) {
            log.info("OIDC Session Management bundle is activated");
        }

        ClaimAdderImp claimAdderImp = new ClaimAdderImp();
        try {
            context.getBundleContext().registerService(ClaimAdder.class.getName(), claimAdderImp, null);
        } catch (Exception e) {
            String msg = "Error when registering ClaimAdder service";
            log.error(msg, e);
            throw new RuntimeException(msg, e);
        }

        if (log.isDebugEnabled()) {
            log.debug("ClaimAdder bundle is activated");
        }
    }

    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.info("OIDC Session Management bundle is deactivated");
        }
    }

    @Reference(
            name = "osgi.http.service",
            service = HttpService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetHttpService"
    )
    protected void setHttpService(HttpService httpService) {

        if (log.isDebugEnabled()) {
            log.info("Setting the HTTP Service in OIDC Session Management bundle");
        }
        OIDCSessionManagementComponentServiceHolder.setHttpService(httpService);
    }

    protected void unsetHttpService(HttpService httpService) {

        if (log.isDebugEnabled()) {
            log.info("Unsetting the HTTP Service in OIDC Session Management bundle");
        }
        OIDCSessionManagementComponentServiceHolder.setHttpService(null);
    }

    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service.");
        }
        OIDCSessionManagementComponentServiceHolder.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the Realm Service.");
        }
        OIDCSessionManagementComponentServiceHolder.setRealmService(null);
    }
}
