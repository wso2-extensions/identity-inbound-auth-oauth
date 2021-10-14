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

package org.wso2.carbon.identity.oauth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthIDTokenAlgorithmDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthTokenExpiryTimeDTO;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.dto.TokenBindingMetaDataDTO;

import java.util.List;

/**
 * OAuth admin service.
 */
public class OAuthAdminService extends AbstractAdmin {

    private static final Log log = LogFactory.getLog(OAuthAdminService.class);
    protected final OAuthAdminServiceImpl oAuthAdminServiceImpl = new OAuthAdminServiceImpl();

    /**
     * Registers an consumer secret against the logged in user. A given user can only have a single
     * consumer secret at a time. Calling this method again and again will update the existing
     * consumer secret key.
     *
     * @return An array containing the consumer key and the consumer secret correspondingly.
     * @throws IdentityOAuthAdminException Error when persisting the data in the persistence store.
     */
    public String[] registerOAuthConsumer() throws IdentityOAuthAdminException {

        try {
            return oAuthAdminServiceImpl.registerOAuthConsumer();
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * Get all registered OAuth applications for the logged in user.
     *
     * @return An array of <code>OAuthConsumerAppDTO</code> objecting containing the application.
     * information of the user
     * @throws IdentityOAuthAdminException Error when reading the data from the persistence store.
     */
    public OAuthConsumerAppDTO[] getAllOAuthApplicationData() throws IdentityOAuthAdminException {

        try {
            return oAuthAdminServiceImpl.getAllOAuthApplicationData();
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * Get OAuth application data by the consumer key.
     *
     * @param consumerKey Consumer Key.
     * @return <code>OAuthConsumerAppDTO</code> with application information.
     * @throws IdentityOAuthAdminException Error when reading application information from persistence store.
     */
    public OAuthConsumerAppDTO getOAuthApplicationData(String consumerKey) throws IdentityOAuthAdminException {

        try {
            return oAuthAdminServiceImpl.getOAuthApplicationData(consumerKey);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * Get OAuth application data by the application name.
     *
     * @param appName OAuth application name.
     * @return <code>OAuthConsumerAppDTO</code> with application information.
     * @throws IdentityOAuthAdminException Error when reading application information from persistence store.
     */
    public OAuthConsumerAppDTO getOAuthApplicationDataByAppName(String appName) throws IdentityOAuthAdminException {

        try {
            return oAuthAdminServiceImpl.getOAuthApplicationDataByAppName(appName);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * Registers an OAuth consumer application.
     *
     * @param application <code>OAuthConsumerAppDTO</code> with application information.
     * @throws IdentityOAuthAdminException Error when persisting the application information to the persistence store.
     */
    public void registerOAuthApplicationData(OAuthConsumerAppDTO application) throws IdentityOAuthAdminException {

        try {
            oAuthAdminServiceImpl.registerOAuthApplicationData(application);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * Registers an OAuth consumer application and retrieve application details.
     *
     * @param application <code>OAuthConsumerAppDTO</code> with application information.
     * @return OAuthConsumerAppDTO Created OAuth application details.
     * @throws IdentityOAuthAdminException Error when persisting the application information to the persistence store.
     */
    public OAuthConsumerAppDTO registerAndRetrieveOAuthApplicationData(OAuthConsumerAppDTO application)
            throws IdentityOAuthAdminException {

        try {
            return oAuthAdminServiceImpl.registerAndRetrieveOAuthApplicationData(application);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * Update existing consumer application.
     *
     * @param consumerAppDTO <code>OAuthConsumerAppDTO</code> with updated application information
     * @throws IdentityOAuthAdminException Error when updating the underlying identity persistence store.
     */
    public void updateConsumerApplication(OAuthConsumerAppDTO consumerAppDTO) throws IdentityOAuthAdminException {

        try {
            oAuthAdminServiceImpl.updateConsumerApplication(consumerAppDTO);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * @return
     * @throws IdentityOAuthAdminException
     */
    public String getOauthApplicationState(String consumerKey) throws IdentityOAuthAdminException {

        try {
            return oAuthAdminServiceImpl.getOauthApplicationState(consumerKey);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * To insert oidc scopes and claims in the related db tables.
     *
     * @param scope an oidc scope.
     * @throws IdentityOAuthAdminException if an error occurs when inserting scopes or claims.
     */
    public void addScope(String scope, String[] claims) throws IdentityOAuthAdminException {

        try {
            oAuthAdminServiceImpl.addScope(scope, claims);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * To retrieve all persisted oidc scopes with mapped claims.
     *
     * @return all persisted scopes and claims.
     * @throws IdentityOAuthAdminException if an error occurs when loading scopes and claims.
     */
    public ScopeDTO[] getScopes() throws IdentityOAuthAdminException {

        try {
            return oAuthAdminServiceImpl.getScopes();
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * To remove persisted scopes and claims.
     *
     * @param scope oidc scope.
     * @throws IdentityOAuthAdminException if an error occurs when deleting scopes and claims.
     */
    public void deleteScope(String scope) throws IdentityOAuthAdminException {

        try {
            oAuthAdminServiceImpl.deleteScope(scope);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * To retrieve all persisted oidc scopes.
     *
     * @return list of scopes persisted.
     * @throws IdentityOAuthAdminException if an error occurs when loading oidc scopes.
     */
    public String[] getScopeNames() throws IdentityOAuthAdminException {

        try {
            return oAuthAdminServiceImpl.getScopeNames();
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * To retrieve oidc claims mapped to an oidc scope.
     *
     * @param scope scope.
     * @return list of claims which are mapped to the oidc scope.
     * @throws IdentityOAuthAdminException if an error occurs when lading oidc claims.
     */
    public String[] getClaims(String scope) throws IdentityOAuthAdminException {

        try {
            return oAuthAdminServiceImpl.getClaims(scope);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * To add new claims for an existing scope.
     *
     * @param scope        scope name.
     * @param addClaims    list of oidc claims to be added.
     * @param deleteClaims list of oidc claims to be deleted.
     * @throws IdentityOAuthAdminException if an error occurs when adding a new claim for a scope.
     */
    public void updateScope(String scope, String[] addClaims, String[] deleteClaims)
            throws IdentityOAuthAdminException {

        try {
            oAuthAdminServiceImpl.updateScope(scope, addClaims, deleteClaims);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * To load id of the scope table.
     *
     * @param scope scope name
     * @return id of the given scope.
     * @throws IdentityOAuthAdminException if an error occurs when loading scope id.
     */
    public boolean isScopeExist(String scope) throws IdentityOAuthAdminException {

        try {
            return oAuthAdminServiceImpl.isScopeExist(scope);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * @param consumerKey
     * @param newState
     * @throws IdentityOAuthAdminException
     */
    public void updateConsumerAppState(String consumerKey, String newState) throws IdentityOAuthAdminException {

        try {
            oAuthAdminServiceImpl.updateConsumerAppState(consumerKey, newState);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * Regenerate consumer secret for the application.
     *
     * @param consumerKey Consumer key for the application.
     * @throws IdentityOAuthAdminException Error while regenerating the consumer secret.
     */
    public void updateOauthSecretKey(String consumerKey) throws IdentityOAuthAdminException {

        try {
            oAuthAdminServiceImpl.updateOauthSecretKey(consumerKey);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * Regenerate consumer secret for the application and retrieve application details.
     *
     * @param consumerKey Consumer key for the application.
     * @return OAuthConsumerAppDTO OAuth application details.
     * @throws IdentityOAuthAdminException Error while regenerating the consumer secret.
     */
    public OAuthConsumerAppDTO updateAndRetrieveOauthSecretKey(String consumerKey) throws IdentityOAuthAdminException {

        try {
            return oAuthAdminServiceImpl.updateAndRetrieveOauthSecretKey(consumerKey);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * Removes an OAuth consumer application.
     *
     * @param consumerKey Consumer Key
     * @throws IdentityOAuthAdminException Error when removing the consumer information from the database.
     */
    public void removeOAuthApplicationData(String consumerKey) throws IdentityOAuthAdminException {

        // remove client credentials from cache.
        try {
            oAuthAdminServiceImpl.removeOAuthApplicationData(consumerKey);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * Get apps that are authorized by the given user
     *
     * @return OAuth applications authorized by the user that have tokens in ACTIVE or EXPIRED state
     */
    public OAuthConsumerAppDTO[] getAppsAuthorizedByUser() throws IdentityOAuthAdminException {

        try {
            return oAuthAdminServiceImpl.getAppsAuthorizedByUser();
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * Revoke authorization for OAuth apps by resource owners
     *
     * @param revokeRequestDTO DTO representing authorized user and apps[]
     * @return revokeRespDTO DTO representing success or failure message
     */
    public OAuthRevocationResponseDTO revokeAuthzForAppsByResoureOwner(
            OAuthRevocationRequestDTO revokeRequestDTO) throws IdentityOAuthAdminException {

        try {
            return oAuthAdminServiceImpl.revokeAuthzForAppsByResourceOwner(revokeRequestDTO);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    /**
     * Revoke approve always of the consent for OAuth apps by resource owners
     *
     * @param appName name of the app
     * @param state   state of the approve always
     * @return revokeRespDTO DTO representing success or failure message
     */
    public OAuthRevocationResponseDTO updateApproveAlwaysForAppConsentByResourceOwner(String appName, String state)
            throws IdentityOAuthAdminException {

        try {
            return oAuthAdminServiceImpl.updateApproveAlwaysForAppConsentByResourceOwner(appName, state);
        } catch (IdentityOAuthAdminException ex) {
            throw handleError(ex);
        }
    }

    public String[] getAllowedGrantTypes() {

        return oAuthAdminServiceImpl.getAllowedGrantTypes();
    }

    /**
     * Get the registered scope validators from OAuth server configuration file.
     *
     * @return List of string containing simple names of the registered validator class.
     */
    public String[] getAllowedScopeValidators() {

        return oAuthAdminServiceImpl.getAllowedScopeValidators();
    }

    /**
     * Get the registered oauth token types from OAuth server configuration file.
     *
     * @return List of supported oauth token types.
     */
    public List<String> getSupportedTokenTypes() {

        return oAuthAdminServiceImpl.getSupportedTokenTypes();
    }

    /**
     * Get the renew refresh token property value from identity.xml file.
     *
     * @return renew refresh token property value.
     */
    public boolean isRefreshTokenRenewalEnabled() {

        return oAuthAdminServiceImpl.isRefreshTokenRenewalEnabled();
    }

    /**
     * @return true if PKCE is supported by the database, false if not.
     */
    public boolean isPKCESupportEnabled() {

        return oAuthAdminServiceImpl.isPKCESupportEnabled();
    }

    public OAuthTokenExpiryTimeDTO getTokenExpiryTimes() {

        return oAuthAdminServiceImpl.getTokenExpiryTimes();
    }

    /**
     * Get supported token bindings meta data.
     *
     * @return list of TokenBindingMetaDataDTOs.
     */
    public List<TokenBindingMetaDataDTO> getSupportedTokenBindingsMetaData() {

        return oAuthAdminServiceImpl.getSupportedTokenBindingsMetaData();
    }

    /**
     * Get supported algorithms from OAuthServerConfiguration and construct an OAuthIDTokenAlgorithmDTO object.
     *
     * @return Constructed OAuthIDTokenAlgorithmDTO object with supported algorithms.
     */
    public OAuthIDTokenAlgorithmDTO getSupportedIDTokenAlgorithms() {

        return oAuthAdminServiceImpl.getSupportedIDTokenAlgorithms();
    }

    /**
     * Check whether hashing oauth keys (consumer secret, access token, refresh token and authorization code)
     * configuration is disabled or not in identity.xml file.
     *
     * @return Whether hash feature is disabled or not.
     */
    public boolean isHashDisabled() {

        return oAuthAdminServiceImpl.isHashDisabled();
    }

    private IdentityOAuthAdminException handleError(IdentityOAuthAdminException ex) {

        if (ex instanceof IdentityOAuthClientException) {
            if (log.isDebugEnabled()) {
                log.debug(ex);
            }
        } else {
            log.error(ex);
        }

        return ex;
    }
}
