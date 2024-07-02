/*
 * Copyright (c) 2024, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.rar.internal;

import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProvider;

import java.util.HashSet;
import java.util.Set;

/**
 * Singleton class that holds rich authorization details data.
 * <p>This class uses the singleton design pattern to ensure there is only one instance
 * managing the authorization details providers. The instance is lazily initialized
 * with double-checked locking to ensure thread safety.</p>
 * <p>The class provides methods to retrieve and set the authorization details data,
 * which can be used in different parts of the application to manage rich authorization details.</p>
 */
public class AuthorizationDetailsDataHolder {

    private static volatile AuthorizationDetailsDataHolder instance;
    private Set<AuthorizationDetailsProvider> authorizationDetailsProviders;

    /**
     * Private constructor to prevent instantiation from outside the class.
     */
    private AuthorizationDetailsDataHolder() {

        this.authorizationDetailsProviders = new HashSet<>();
    }

    /**
     * Returns the singleton instance of {@link AuthorizationDetailsDataHolder}.
     *
     * <p>This method uses double-checked locking to ensure that the instance is initialized
     * only once and in a thread-safe manner. If the instance is not already created, it
     * will be created and returned; otherwise, the existing instance will be returned.</p>
     *
     * @return The singleton instance of {@link AuthorizationDetailsDataHolder}.
     */
    public static AuthorizationDetailsDataHolder getInstance() {

        if (instance == null) {
            synchronized (AuthorizationDetailsDataHolder.class) {
                if (instance == null) {
                    instance = new AuthorizationDetailsDataHolder();
                }
            }
        }
        return instance;
    }

    /**
     * Returns the current set of {@link AuthorizationDetailsProvider} instances.
     *
     * <p>This method provides access to the authorization details providers.
     * The returned set can be used to query or modify the authorization details providers.</p>
     *
     * @return A {@link Set} of {@link AuthorizationDetailsProvider} instances.
     */
    public Set<AuthorizationDetailsProvider> getAuthorizationDetailsProviders() {

        return this.authorizationDetailsProviders;
    }

    /**
     * Sets the set of {@link AuthorizationDetailsProvider} instances to the provided value.
     *
     * <p>This method replaces the current set of authorization details providers with the
     * provided set. It can be used to update the list of providers that the application
     * uses to manage authorization details.</p>
     *
     * @param authorizationDetailsProviders The new {@link Set} of {@link AuthorizationDetailsProvider} instances.
     */
    public void setAuthorizationDetailsProviders(Set<AuthorizationDetailsProvider> authorizationDetailsProviders) {

        this.authorizationDetailsProviders = authorizationDetailsProviders;
    }
}
