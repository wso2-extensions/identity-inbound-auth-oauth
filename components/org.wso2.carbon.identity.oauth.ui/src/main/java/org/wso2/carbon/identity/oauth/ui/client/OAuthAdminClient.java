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

package org.wso2.carbon.identity.oauth.ui.client;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.lang.ArrayUtils;
import org.wso2.carbon.identity.oauth.stub.OAuthAdminServiceIdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.stub.OAuthAdminServiceStub;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthIDTokenAlgorithmDTO;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthTokenExpiryTimeDTO;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth.stub.dto.ScopeDTO;

import java.rmi.RemoteException;
import java.util.List;

public class OAuthAdminClient {

    private static String[] allowedGrantTypes = null;
    private static String[] scopeValidators = null;
    private String[] supportedTokenTypes = ArrayUtils.EMPTY_STRING_ARRAY;
    private OAuthAdminServiceStub stub;

    /**
     * Instantiates OAuthAdminClient
     *
     * @param cookie           For session management
     * @param backendServerURL URL of the back end server where OAuthAdminService is running.
     * @param configCtx        ConfigurationContext
     * @throws org.apache.axis2.AxisFault
     */
    public OAuthAdminClient(String cookie, String backendServerURL, ConfigurationContext configCtx)
            throws AxisFault {

        String serviceURL = backendServerURL + "OAuthAdminService";
        stub = new OAuthAdminServiceStub(configCtx, serviceURL);
        ServiceClient client = stub._getServiceClient();
        Options option = client.getOptions();
        option.setManageSession(true);
        option.setProperty(org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, cookie);
    }

    public OAuthConsumerAppDTO[] getAllOAuthApplicationData() throws Exception {

        return stub.getAllOAuthApplicationData();
    }

    public OAuthConsumerAppDTO getOAuthApplicationData(String consumerkey) throws Exception {

        return stub.getOAuthApplicationData(consumerkey);
    }

    public OAuthConsumerAppDTO getOAuthApplicationDataByAppName(String appName) throws Exception {

        return stub.getOAuthApplicationDataByAppName(appName);
    }

    // TODO : this method should return app data
    public void registerOAuthApplicationData(OAuthConsumerAppDTO application) throws Exception {

        stub.registerOAuthApplicationData(application);
    }

    /**
     * Registers an OAuth consumer application and retrieve application details.
     *
     * @param application <code>OAuthConsumerAppDTO</code> with application information.
     * @return OAuthConsumerAppDTO Created OAuth application details.
     * @throws Exception Error while registering an application.
     */
    public OAuthConsumerAppDTO registerAndRetrieveOAuthApplicationData(OAuthConsumerAppDTO application)
            throws Exception {

        return stub.registerAndRetrieveOAuthApplicationData(application);
    }

    // TODO : this method should be removed once above is done
    public OAuthConsumerAppDTO getOAuthApplicationDataByName(String applicationName) throws Exception {

        OAuthConsumerAppDTO[] dtos = stub.getAllOAuthApplicationData();
        if (dtos != null && dtos.length > 0) {
            for (OAuthConsumerAppDTO dto : dtos) {
                if (applicationName.equals(dto.getApplicationName())) {
                    return dto;
                }
            }
        }
        return null;

    }

    public void removeOAuthApplicationData(String consumerkey) throws Exception {

        stub.removeOAuthApplicationData(consumerkey);
    }

    public void updateOAuthApplicationData(OAuthConsumerAppDTO consumerAppDTO) throws Exception {

        stub.updateConsumerApplication(consumerAppDTO);
    }

    public OAuthConsumerAppDTO[] getAppsAuthorizedByUser() throws Exception {

        return stub.getAppsAuthorizedByUser();
    }

    public OAuthRevocationResponseDTO revokeAuthzForAppsByRessourceOwner(OAuthRevocationRequestDTO reqDTO) throws Exception {

        return stub.revokeAuthzForAppsByResoureOwner(reqDTO);
    }

    public boolean isPKCESupportedEnabled() throws Exception {

        return stub.isPKCESupportEnabled();
    }

    /**
     * Check whether hashing oauth keys (consumer secret, access token, refresh token and authorization code)
     * configuration is disabled or not in identity.xml file.
     *
     * @return Whether hash feature is disabled or not.
     * @throws Exception Error while getting the oAuth configuration.
     */
    public boolean isHashDisabled() throws Exception {

        return stub.isHashDisabled();
    }

    public String[] getAllowedOAuthGrantTypes() throws Exception {

        if (allowedGrantTypes == null) {
            allowedGrantTypes = stub.getAllowedGrantTypes();
        }
        return allowedGrantTypes;
    }

    public void regenerateSecretKey(String consumerkey) throws Exception {

        stub.updateOauthSecretKey(consumerkey);
    }

    /**
     * Regenerate consumer secret for the application and retrieve application details.
     *
     * @param consumerKey Consumer key for the application.
     * @return OAuthConsumerAppDTO oAuth application details.
     * @throws Exception Error while regenerating the consumer secret.
     */
    public OAuthConsumerAppDTO regenerateAndRetrieveOauthSecretKey(String consumerKey) throws Exception {

        return stub.updateAndRetrieveOauthSecretKey(consumerKey);
    }

    public String getOauthApplicationState(String consumerKey) throws Exception {

        return stub.getOauthApplicationState(consumerKey);
    }

    public void updateOauthApplicationState(String consumerKey, String newState) throws Exception {

        stub.updateConsumerAppState(consumerKey, newState);
    }

    public OAuthTokenExpiryTimeDTO getOAuthTokenExpiryTimeDTO() throws RemoteException {

        return stub.getTokenExpiryTimes();
    }

    /**
     * To add oidc scopes and claims
     *
     * @param scope an OIDC scope
     * @throws RemoteException                              if an exception occured during remote call.
     * @throws OAuthAdminServiceIdentityOAuthAdminException if an error occurs when adding scopes or claims
     */
    public void addScope(String scope, String[] claims) throws RemoteException,
            OAuthAdminServiceIdentityOAuthAdminException {

        stub.addScope(scope, claims);
    }

    /**
     * To retrieve all persisted oidc scopes with mapped claims.
     *
     * @return all persisted scopes and claims
     * @throws RemoteException                              if an exception occured during remote call.
     * @throws OAuthAdminServiceIdentityOAuthAdminException if an error occurs when loading scopes and claims.
     */

    public ScopeDTO[] getScopes() throws OAuthAdminServiceIdentityOAuthAdminException,
            RemoteException {

        return stub.getScopes();
    }

    /**
     * To retrieve all persisted oidc scopes.
     *
     * @return list of scopes persisted.
     * @throws OAuthAdminServiceIdentityOAuthAdminException if an error occurs when loading oidc scopes.
     * @throws RemoteException                              if an exception occured during remote call.
     */
    public String[] getScopeNames() throws OAuthAdminServiceIdentityOAuthAdminException,
            RemoteException {

        return stub.getScopeNames();
    }

    /**
     * To retrieve oidc claims mapped to an oidc scope.
     *
     * @param scope scope name
     * @return list of claims which are mapped to the oidc scope.
     * @throws OAuthAdminServiceIdentityOAuthAdminException if an error occurs when lading oidc claims.
     * @throws RemoteException                              if an exception occured during remote call.
     */
    public String[] getClaims(String scope) throws OAuthAdminServiceIdentityOAuthAdminException,
            RemoteException {

        return stub.getClaims(scope);
    }

    /**
     * To load scope id.
     *
     * @param scope scope name
     * @return oidc scope id
     * @throws OAuthAdminServiceIdentityOAuthAdminException if an error occurs while loading scope id.
     * @throws RemoteException                              if an exception occured during remote call.
     */
    public boolean isScopeExist(String scope) throws OAuthAdminServiceIdentityOAuthAdminException, RemoteException {

        return stub.isScopeExist(scope);
    }

    /**
     * To remove persisted scopes and claims.
     *
     * @param scope@throws OAuthAdminServiceIdentityOAuthAdminException if an error occurs when deleting scopes and claims.
     * @throws RemoteException if an exception occured during remote call.
     */
    public void deleteScope(String scope)
            throws OAuthAdminServiceIdentityOAuthAdminException, RemoteException {

        stub.deleteScope(scope);
    }

    /**
     * To add new claims for an existing scope.
     *
     * @param scope     scope name
     * @param addClaims addClaims
     * @throws RemoteException                          if an exception occured during remote call.
     * @throws OAuthAdminServiceIdentityOAuthAdminException if an error occurs when adding new claims for scope.
     */
    public void updateScope(String scope, String[] addClaims, String[] deleteClaims) throws RemoteException,
            OAuthAdminServiceIdentityOAuthAdminException {

        stub.updateScope(scope, addClaims, deleteClaims);
    }

    /**
     * Get the registered scope validators from OAuth server configuration file.
     *
     * @return list of string containing simple names of the registered validator class
     * @throws RemoteException exception occured during remote call
     */
    public String[] getAllowedScopeValidators() throws RemoteException {

        if (scopeValidators == null) {
            scopeValidators = stub.getAllowedScopeValidators();
            if (scopeValidators == null) {
                scopeValidators = new String[0];
            }
        }
        return scopeValidators;
    }

    /**
     * Get the registered oauth token types from OAuth server configuration file.
     *
     * @return List of supported oauth token types
     * @throws RemoteException exception occured during remote call
     */
    public String[] getSupportedTokenTypes() throws RemoteException {

        if (stub.getSupportedTokenTypes() != null) {
            supportedTokenTypes = stub.getSupportedTokenTypes();
        }
        return supportedTokenTypes;
    }

    /**
     * Return supported algorithms read from identity.xml configuration file.
     *
     * @return OAuthIDTokenAlgorithmDTO object.
     * @throws RemoteException
     */
    public OAuthIDTokenAlgorithmDTO getSupportedIDTokenAlgorithms() throws RemoteException {

        return stub.getSupportedIDTokenAlgorithms();
    }

    /**
     * Return renew refresh token property value read from identity.xml configuration file.
     *
     * @return boolean renew refresh token property value
     * @throws RemoteException
     */
    public boolean isRefreshTokenRenewalEnabled() throws RemoteException {

        return stub.isRefreshTokenRenewalEnabled();
    }
}
