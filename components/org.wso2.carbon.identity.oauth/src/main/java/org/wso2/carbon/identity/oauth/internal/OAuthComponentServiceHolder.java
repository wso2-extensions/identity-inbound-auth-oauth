/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.OAuthService;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.registry.api.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

public class OAuthComponentServiceHolder {

    private static OAuthComponentServiceHolder instance = new OAuthComponentServiceHolder();
    private RegistryService registryService;
    private RealmService realmService;
    private OAuthEventInterceptor oAuthEventInterceptorHandlerProxy;
    private OAuth2Service oauth2Service;
    private static Log log = LogFactory.getLog(OAuthComponentServiceHolder.class);

    private OAuthComponentServiceHolder() {

    }

    public static OAuthComponentServiceHolder getInstance() {

        return instance;
    }

    public RegistryService getRegistryService() {

        return registryService;
    }

    public void setRegistryService(RegistryService registryService) {

        this.registryService = registryService;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public void addOauthEventInterceptorProxy(OAuthEventInterceptor oAuthEventInterceptorHandlerProxy) {
        this.oAuthEventInterceptorHandlerProxy = oAuthEventInterceptorHandlerProxy;
    }

    public OAuthEventInterceptor getOAuthEventInterceptorProxy() {
        return this.oAuthEventInterceptorHandlerProxy;
    }

    public OAuth2Service getOauth2Service() {
        return oauth2Service;
    }

    public void setOauth2Service(OAuth2Service oauth2Service) {
        this.oauth2Service = oauth2Service;
    }
}
