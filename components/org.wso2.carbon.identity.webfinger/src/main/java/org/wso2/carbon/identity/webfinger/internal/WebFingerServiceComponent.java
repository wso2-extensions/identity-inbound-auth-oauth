/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.webfinger.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.equinox.http.helper.ContextPathServletAdaptor;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.webfinger.DefaultWebFingerProcessor;
import org.wso2.carbon.identity.webfinger.WebFingerProcessor;
import org.wso2.carbon.identity.webfinger.servlet.WebFingerServlet;
import org.wso2.carbon.user.core.service.RealmService;

import javax.servlet.Servlet;

/**
 * @scr.component name="identity.webfinger.component" immediate="true"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService" cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 * @scr.reference name="osgi.httpservice" interface="org.osgi.service.http.HttpService"
 * cardinality="1..1" policy="dynamic" bind="setHttpService"
 * unbind="unsetHttpService"
 */

public class WebFingerServiceComponent {
    private static Log log = LogFactory.getLog(WebFingerServiceComponent.class);
    private static BundleContext bundleContext = null;

    public static BundleContext getBundleContext() {
        return bundleContext;
    }

    protected void activate(ComponentContext context) {
        try {
            synchronized (this) {
                bundleContext = context.getBundleContext();
            }
            WebFingerProcessor webFingerProcessor = DefaultWebFingerProcessor.getInstance();
            bundleContext.registerService(WebFingerProcessor.class.getName(), webFingerProcessor, null);
            WebFingerServiceComponentHolder.setWebFingerProcessor(webFingerProcessor);
            if (log.isDebugEnabled()) {
                log.debug("OpenID WebFinger bundle is activated.");
            }

            // Register OpenID Connect WebFinger servlet
            HttpService httpService = WebFingerServiceComponentHolder.getHttpService();
            Servlet webFingerServlet = new ContextPathServletAdaptor(new WebFingerServlet(),
                    "/.well-known/webfinger");
            try {
                httpService.registerServlet("/.well-known/webfinger", webFingerServlet, null, null);
            } catch (Exception e) {
                String errMsg = "Error when registering Web Finger Servlet via the HttpService.";
                log.error(errMsg, e);
                throw new RuntimeException(errMsg, e);
            }
        } catch (Throwable e) {
            log.error("Error while activating the WebFingerServiceComponent", e);
        }
    }

    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.info("Setting the Realm Service");
        }
        WebFingerServiceComponentHolder.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.info("Unsetting the Realm Service");
        }
        WebFingerServiceComponentHolder.setRealmService(null);
    }

    protected void setHttpService(HttpService httpService) {
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is set in the OpenID Connect WebFinger bundle");
        }
        WebFingerServiceComponentHolder.setHttpService(httpService);
    }

    protected void unsetHttpService(HttpService httpService) {
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is unset in the OpenID Connect WebFinger bundle");
        }
        WebFingerServiceComponentHolder.setHttpService(null);
    }
}
