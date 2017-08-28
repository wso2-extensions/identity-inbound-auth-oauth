    /*
 * Copyright (c) 2012, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.authcontext;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.util.ClaimCache;
import org.wso2.carbon.identity.oauth.util.ClaimCacheKey;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCache;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCacheEntry;
import org.wso2.carbon.identity.oauth.util.ClaimMetaDataCacheKey;
import org.wso2.carbon.identity.oauth.util.UserClaims;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.security.Key;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This class represents the JSON Web Token generator.
 * By default the following properties are encoded to each authenticated API request:
 * subscriber, applicationName, apiContext, version, tier, and endUserName
 * Additional properties can be encoded by engaging the ClaimsRetrieverImplClass callback-handler.
 * The JWT header and body are base64 encoded separately and concatenated with a dot.
 * Finally the token is signed using SHA256 with RSA algorithm.
 */
public class JWTTokenGenerator implements AuthorizationContextTokenGenerator {

    private static final Log log = LogFactory.getLog(JWTTokenGenerator.class);

    private static final String API_GATEWAY_ID = "http://wso2.org/gateway";

    private static final String NONE = "NONE";

    private static volatile long ttl = -1L;

    private ClaimsRetriever claimsRetriever;

    private JWSAlgorithm signatureAlgorithm = new JWSAlgorithm(JWSAlgorithm.RS256.getName());

    private boolean includeClaims = true;

    private boolean enableSigning = true;

    private static Map<Integer, Key> privateKeys = new ConcurrentHashMap<Integer, Key>();
    private static Map<Integer, Certificate> publicCerts = new ConcurrentHashMap<Integer, Certificate>();

    private ClaimCache claimsLocalCache;

    public JWTTokenGenerator() {
        claimsLocalCache = ClaimCache.getInstance();
    }

    private String userAttributeSeparator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;

    private boolean useMultiValueSeparator = true;


    //constructor for testing purposes
    public JWTTokenGenerator(boolean includeClaims, boolean enableSigning) {
        this.includeClaims = includeClaims;
        this.enableSigning = enableSigning;
        signatureAlgorithm = new JWSAlgorithm(JWSAlgorithm.NONE.getName());

    }

    /**
     * Reads the ClaimsRetrieverImplClass from identity.xml ->
     * OAuth -> TokenGeneration -> ClaimsRetrieverImplClass.
     *
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void init() throws IdentityOAuth2Exception {
        if (includeClaims && enableSigning) {
            String claimsRetrieverImplClass = OAuthServerConfiguration.getInstance().getClaimsRetrieverImplClass();
            String sigAlg =  OAuthServerConfiguration.getInstance().getSignatureAlgorithm();
            if(sigAlg != null && !sigAlg.trim().isEmpty()){
                signatureAlgorithm = OAuth2Util.mapSignatureAlgorithm(sigAlg);
            }
            useMultiValueSeparator = OAuthServerConfiguration.getInstance().isUseMultiValueSeparatorForAuthContextToken();
            if(claimsRetrieverImplClass != null){
                try{
                    claimsRetriever = (ClaimsRetriever)Class.forName(claimsRetrieverImplClass).newInstance();
                    claimsRetriever.init();
                } catch (ClassNotFoundException e){
                    log.error("Cannot find class: " + claimsRetrieverImplClass, e);
                } catch (InstantiationException e) {
                    log.error("Error instantiating " + claimsRetrieverImplClass, e);
                } catch (IllegalAccessException e) {
                    log.error("Illegal access to " + claimsRetrieverImplClass, e);
                } catch (IdentityOAuth2Exception e){
                    log.error("Error while initializing " + claimsRetrieverImplClass, e);
                }
            }
        }
    }

    /**
     * Method that generates the JWT.
     *
     * @return signed JWT token
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void generateToken(OAuth2TokenValidationMessageContext messageContext) throws IdentityOAuth2Exception {

        AccessTokenDO accessTokenDO = (AccessTokenDO)messageContext.getProperty("AccessTokenDO");
        String clientId = accessTokenDO.getConsumerKey();
        long issuedTime = accessTokenDO.getIssuedTime().getTime();
        String authzUser = messageContext.getResponseDTO().getAuthorizedUser();
        int tenantId = accessTokenDO.getTenantID();
        String tenantDomain = OAuth2Util.getTenantDomain(tenantId);
        boolean isExistingUser = false;
        String tenantAwareUsername = null;

        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
        tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(authzUser);

        if (realmService != null && tenantId != MultitenantConstants.INVALID_TENANT_ID && !(accessTokenDO
                .getAuthzUser().isFederatedUser() && !OAuthServerConfiguration.getInstance()
                .isMapFederatedUsersToLocal())) {
            try {
                UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
                if (userRealm != null) {
                    UserStoreManager userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
                    isExistingUser = userStoreManager.isExistingUser(tenantAwareUsername);
                }
            } catch (UserStoreException e) {
                log.error("Error occurred while loading the realm service", e);
            }
        }

        OAuthAppDAO appDAO =  new OAuthAppDAO();
        OAuthAppDO appDO;
        try {
            appDO = appDAO.getAppInformation(clientId);
            // Adding the OAuthAppDO as a context property for further use
            messageContext.addProperty("OAuthAppDO", appDO);
        } catch (IdentityOAuth2Exception e) {
            log.debug(e.getMessage(), e);
            throw new IdentityOAuth2Exception(e.getMessage());
        } catch (InvalidOAuthClientException e) {
            log.debug(e.getMessage(), e);
            throw new IdentityOAuth2Exception(e.getMessage());
        }
        String subscriber = appDO.getUser().toString();
        String applicationName = appDO.getApplicationName();

        //generating expiring timestamp
        long currentTime = Calendar.getInstance().getTimeInMillis();
        long expireIn = currentTime + 1000 * 60 * getTTL();

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet();
        claimsSet.setIssuer(API_GATEWAY_ID);
        claimsSet.setSubject(authzUser);
        claimsSet.setIssueTime(new Date(issuedTime));
        claimsSet.setExpirationTime(new Date(expireIn));
        claimsSet.setClaim(API_GATEWAY_ID+"/subscriber",subscriber);
        claimsSet.setClaim(API_GATEWAY_ID+"/applicationname",applicationName);
        claimsSet.setClaim(API_GATEWAY_ID+"/enduser",authzUser);

        if(claimsRetriever != null){

            //check in local cache
            String[] requestedClaims = messageContext.getRequestDTO().getRequiredClaimURIs();
            if(requestedClaims == null && isExistingUser)  {
                // if no claims were requested, return all
                requestedClaims = claimsRetriever.getDefaultClaims(authzUser);
            }

            ClaimCacheKey cacheKey = null;
            UserClaims result = null;

            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
            authenticatedUser.setUserName(UserCoreUtil.removeDomainFromName(tenantAwareUsername));
            authenticatedUser.setUserStoreDomain(IdentityUtil.extractDomainFromName(tenantAwareUsername));
            authenticatedUser.setTenantDomain(tenantDomain);

            if (requestedClaims != null) {
                cacheKey = new ClaimCacheKey(authenticatedUser);
                result = claimsLocalCache.getValueFromCache(cacheKey);
            }

            SortedMap<String,String> claimValues = null;
            if (result != null) {
                claimValues = result.getClaimValues();
            } else if (isExistingUser) {
                claimValues = claimsRetriever.getClaims(authzUser, requestedClaims);
                UserClaims userClaims = new UserClaims(claimValues);
                claimsLocalCache.addToCache(cacheKey, userClaims);

                ClaimMetaDataCache.getInstance().addToCache(new ClaimMetaDataCacheKey(authenticatedUser),
                        new ClaimMetaDataCacheEntry(cacheKey));
            }

            if(isExistingUser) {
                String claimSeparator = getMultiAttributeSeparator(authzUser, tenantId);
                if (StringUtils.isNotBlank(claimSeparator)) {
                    userAttributeSeparator = claimSeparator;
                }
            }

            if(claimValues != null) {
                Iterator<String> it = new TreeSet(claimValues.keySet()).iterator();
                while (it.hasNext()) {
                    String claimURI = it.next();
                    String claimVal = claimValues.get(claimURI);
                    List<String> claimList = new ArrayList<String>();
                    if (useMultiValueSeparator && userAttributeSeparator != null &&
                            claimVal.contains(userAttributeSeparator)) {
                        StringTokenizer st = new StringTokenizer(claimVal, userAttributeSeparator);
                        while (st.hasMoreElements()) {
                            String attValue = st.nextElement().toString();
                            if (StringUtils.isNotBlank(attValue)) {
                                claimList.add(attValue);
                            }
                        }
                        claimsSet.setClaim(claimURI, claimList.toArray(new String[claimList.size()]));
                    } else {
                        claimsSet.setClaim(claimURI, claimVal);
                    }
                }
            }
        }

        String jwt = null;
        if(!JWSAlgorithm.NONE.equals(signatureAlgorithm)){
            jwt = OAuth2Util.signJWT(claimsSet, signatureAlgorithm, tenantDomain);
        } else {
            jwt = new PlainJWT(claimsSet).serialize();
        }

        if (log.isDebugEnabled()) {
            log.debug("JWT Assertion Value : " + jwt);
        }
        OAuth2TokenValidationResponseDTO.AuthorizationContextToken token;
        token = messageContext.getResponseDTO().new AuthorizationContextToken("JWT", jwt);
        messageContext.getResponseDTO().setAuthorizationContextToken(token);
    }

    private long getTTL() {
        if (ttl != -1) {
            return ttl;
        }

        synchronized (JWTTokenGenerator.class) {
            if (ttl != -1) {
                return ttl;
            }
            String ttlValue = OAuthServerConfiguration.getInstance().getAuthorizationContextTTL();
            if (ttlValue != null) {
                ttl = Long.parseLong(ttlValue);
            } else {
                ttl = 15L;
            }
            return ttl;
        }
    }

    private String getMultiAttributeSeparator(String authenticatedUser, int tenantId) {
        String claimSeparator = null;
        String userDomain = IdentityUtil.extractDomainFromName(authenticatedUser);

        try {
            RealmConfiguration realmConfiguration = null;
            RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();

            if (realmService != null && tenantId != MultitenantConstants.INVALID_TENANT_ID) {
                UserStoreManager userStoreManager = (UserStoreManager) realmService.getTenantUserRealm(tenantId)
                        .getUserStoreManager();
                realmConfiguration = userStoreManager.getSecondaryUserStoreManager(userDomain).getRealmConfiguration();
            }

            if (realmConfiguration != null) {
                claimSeparator = realmConfiguration.getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
                if (claimSeparator != null && !claimSeparator.trim().isEmpty()) {
                    return claimSeparator;
                }
            }
        } catch (UserStoreException e) {
            log.error("Error occurred while getting the realm configuration, User store properties might not be " +
                      "returned", e);
        }
        return null;
    }
}
