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

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.io.IOException;
import java.util.Properties;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * An extension point provided to verify whether the authenticated user is the rightful owner of
 * the resource. There can be multiple active <code>OAuthCallbackHandler</code>
 * implementations at a given time. There are registered through the identity.xml. It has the
 * following configuration.
 * {@code
 * <AuthorizationCallbackHandler Class="org.oauth.samlple.AuthzHandler">
 * <Priority>10</Priority>
 * <Properties>
 * <Property Name="param1">value1</Property>
 * </Properties>
 * </AuthorizationCallbackHandler>
 * }
 * In run-time, each and every authorization callback handler is invoked to see whether it can handle
 * the given callback. Then the callback with the highest priority will be chosen.
 * <p/>
 * After handling the callback, it can set whether the given callback is authorized or not.
 */
public interface OAuthCallbackHandler extends CallbackHandler {

    /**
     * Returns the priority of the callback handler
     *
     * @return priority as a positive integer
     */
    public int getPriority();

    /**
     * Set the priority of the callback handler
     *
     * @param priority integer value of the callback handler
     */
    public void setPriority(int priority);

    /**
     * Whether the given callback can be handled or not.
     *
     * @param callbacks An array of <Code>OAuthCallback</Code>
     * @return <code>true</code> if it can handle the callback.
     * @throws IdentityOAuth2Exception Error while checking the possibility of handling the callback.
     */
    public abstract boolean canHandle(Callback[] callbacks) throws IdentityOAuth2Exception;

    @Override
    public abstract void handle(Callback[] callbacks) throws IOException,
            UnsupportedCallbackException;

    /**
     * Pass the configuration parameters required by the callback handler. These properties can be
     * set through the property elements of the AuthorizationCallbackHandler configuration in
     * identity.xml
     *
     * @param props <code>Properties</code> object populated with the property elements in
     *              the AuthorizationCallbackHandler config.
     */
    public void setProperties(Properties props);
}
