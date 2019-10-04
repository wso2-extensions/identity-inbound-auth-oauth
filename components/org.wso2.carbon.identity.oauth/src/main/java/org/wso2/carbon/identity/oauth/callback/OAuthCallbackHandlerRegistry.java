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

package org.wso2.carbon.identity.oauth.callback;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.config.OAuthCallbackHandlerMetaData;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.utils.CarbonUtils;

import javax.security.auth.callback.Callback;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

/**
 * This is used to maintain the list of OAuthCallback Handlers registered in the system. It handles
 * <Code>OAuthCallbackHandler</Code>, etc which are called during the OAuth token
 * issuance process.
 */
public class OAuthCallbackHandlerRegistry {

    private static final Log log = LogFactory.getLog(OAuthCallbackHandlerRegistry.class);

    private static OAuthCallbackHandlerRegistry instance;

    private transient boolean initAuthzHandlers = false;

    private OAuthCallbackHandler[] authzCallbackHandlers;

    private OAuthCallbackHandlerRegistry() throws IdentityOAuth2Exception {
        initAuthzCallbackHandlers();
    }

    public static OAuthCallbackHandlerRegistry getInstance() throws IdentityOAuth2Exception {

        CarbonUtils.checkSecurity();

        if (instance == null) {
            synchronized (OAuthCallbackHandlerRegistry.class) {
                if (instance == null) {
                    instance = new OAuthCallbackHandlerRegistry();
                }
            }
        }
        return instance;
    }

    /**
     * Initialize the OAuthAuthorizationCallbackHandlers. This is a one-time operation.
     *
     * @throws IdentityOAuth2Exception Error when instantiating the
     *                                 OAuthCallbackHandler instances
     */
    private void initAuthzCallbackHandlers() throws IdentityOAuth2Exception {
        if (!initAuthzHandlers) {
            synchronized (this) {
                if (!initAuthzHandlers) {
                    if (log.isDebugEnabled()) {
                        log.debug("initializing the OAuth Authorization Callback Handlers.");
                    }
                    List<OAuthCallbackHandler> oauthAuthzHandlers = new ArrayList<>();
                    Set<OAuthCallbackHandlerMetaData> callbackHandlerMetaData =
                            OAuthServerConfiguration.getInstance().getCallbackHandlerMetaData();
                    // create an object of each OAuthCallbackHandler registered.
                    for (OAuthCallbackHandlerMetaData metaData : callbackHandlerMetaData) {

                        String className = metaData.getClassName();
                        if (className.length() > 0) { //TODO - Check this
                            Class clazz;
                            OAuthCallbackHandler callbackHandler;

                            try {
                                clazz = this.getClass().getClassLoader().loadClass(metaData.getClassName());
                                callbackHandler = (OAuthCallbackHandler) clazz.newInstance();
                                callbackHandler.setPriority(metaData.getPriority());
                                callbackHandler.setProperties(metaData.getProperties());
                                oauthAuthzHandlers.add(callbackHandler);

                                if (log.isDebugEnabled()) {
                                    log.debug("Instantiated an OAuth Authorization Callback Handler. Class : " + clazz
                                            .getName());
                                }

                            } catch (ClassNotFoundException e) {
                                throw new IdentityOAuth2Exception("Error when loading the OAuthCallbackHandler : " +
                                        className, e);
                            } catch (InstantiationException | IllegalAccessException e) {
                                throw new IdentityOAuth2Exception("Error when instantiating the OAuthCallbackHandler : "
                                        + className, e);
                            }
                        }
                    }

                    if (log.isDebugEnabled()) {
                        log.debug("Finished initializing OAuth Authorization Callback Handlers. No. of Authz Handlers" +
                                " registered : " + oauthAuthzHandlers.size());
                    }

                    authzCallbackHandlers = oauthAuthzHandlers.toArray(
                            new OAuthCallbackHandler[oauthAuthzHandlers.size()]);
                    // sort the OAuth Authorization Handlers based on priorities.
                    Arrays.sort(authzCallbackHandlers, new OAuthAuthzCbHandlerComparator());
                    initAuthzHandlers = true;
                }
            }
        }
    }

    /**
     * Get the appropriate <Code>OAuthCallbackHandler</Code> for the given callback
     *
     * @param authzCallback <Code>OAuthCallback</Code> object
     * @return <Code>OAuthCallbackHandler</Code> instance which can handle the
     * given callback, return <Code>null</Code> if there is no OAuthCallbackHandler which
     * can handle the given callback
     * @throws IdentityOAuth2Exception Error while evaluating the canHandle method
     */
    public OAuthCallbackHandler getOAuthAuthzHandler(
            OAuthCallback authzCallback) throws IdentityOAuth2Exception {

        for (OAuthCallbackHandler oauthAuthzCbHandler : authzCallbackHandlers) {
            if (oauthAuthzCbHandler.canHandle(new Callback[]{authzCallback})) {
                if (log.isDebugEnabled()) {
                    log.debug("OAuthCallbackHandler was found for the callback. Class Name : " + oauthAuthzCbHandler
                            .getClass().getName() + " Resource Owner : " + authzCallback.getResourceOwner() + " " +
                            "Client Id : " + authzCallback.getClient() + " Scope : " + OAuth2Util.buildScopeString
                            (authzCallback.getRequestedScope()));
                }
                return oauthAuthzCbHandler;
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("No OAuthAuthorizationCallbackHandlers were found for the callback. Resource Owner : " +
                    authzCallback.getResourceOwner() + " Client Id : " + authzCallback.getClient() + " Scope : " +
                    OAuth2Util.buildScopeString(authzCallback.getRequestedScope()));
        }
        return null;
    }

    /**
     * Comparator for OAuthCallbackHandler based on their priority.
     */
    private class OAuthAuthzCbHandlerComparator implements Comparator<OAuthCallbackHandler> {

        @Override
        public int compare(OAuthCallbackHandler o1, OAuthCallbackHandler o2) {
            return o1.getPriority() - o2.getPriority();
        }
    }
}
