/*
 * Copyright (c) 2012-2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.authcontext;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
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
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;

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
            String sigAlg = OAuthServerConfiguration.getInstance().getSignatureAlgorithm();
            if (sigAlg != null && !sigAlg.trim().isEmpty()) {
                signatureAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(sigAlg);
            }
            useMultiValueSeparator =
                    OAuthServerConfiguration.getInstance().isUseMultiValueSeparatorForAuthContextToken();
            if (claimsRetrieverImplClass != null) {
                try {
                    claimsRetriever = (ClaimsRetriever) Class.forName(claimsRetrieverImplClass).newInstance();
                    claimsRetriever.init();
                } catch (ClassNotFoundException e) {
                    log.error("Cannot find class: " + claimsRetrieverImplClass, e);
                } catch (InstantiationException e) {
                    log.error("Error instantiating " + claimsRetrieverImplClass, e);
                } catch (IllegalAccessException e) {
                    log.error("Illegal access to " + claimsRetrieverImplClass, e);
                } catch (IdentityOAuth2Exception e) {
                    log.error("Error while initializing " + claimsRetrieverImplClass, e);
                }
            }
        }
    }

    /**
     * Method that generates the JWT.
     *
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void generateToken(OAuth2TokenValidationMessageContext messageContext) throws IdentityOAuth2Exception {

        AccessTokenDO accessTokenDO = (AccessTokenDO) messageContext.getProperty("AccessTokenDO");
        String clientId = accessTokenDO.getConsumerKey();
        long issuedTime = accessTokenDO.getIssuedTime().getTime();
        long validityPeriodInMillis = accessTokenDO.getValidityPeriodInMillis();
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

        OAuthAppDAO appDAO = new OAuthAppDAO();
        OAuthAppDO appDO;
        try {
            appDO = appDAO.getAppInformation(clientId);
            // Adding the OAuthAppDO as a context property for further use
            messageContext.addProperty("OAuthAppDO", appDO);
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            log.debug(e.getMessage(), e);
            throw new IdentityOAuth2Exception(e.getMessage());
        }
        String subscriber = appDO.getAppOwner().toString();
        String applicationName = appDO.getApplicationName();

        //generating expiring timestamp
        long currentTime = Calendar.getInstance().getTimeInMillis();
        // Expiry time of the JWT.
        long expireIn = validityPeriodInMillis + issuedTime;

        // Prepare JWT with claims set
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
        claimsSetBuilder.issuer(API_GATEWAY_ID);
        claimsSetBuilder.subject(authzUser);
        claimsSetBuilder.issueTime(new Date(currentTime));
        claimsSetBuilder.expirationTime(new Date(expireIn));
        // Nbf is set to the issue time of the JWT and not the issue time of the access token.
        claimsSetBuilder.notBeforeTime(new Date(currentTime));
        claimsSetBuilder.claim(API_GATEWAY_ID + "/subscriber", subscriber);
        claimsSetBuilder.claim(API_GATEWAY_ID + "/applicationname", applicationName);
        claimsSetBuilder.claim(API_GATEWAY_ID + "/enduser", authzUser);
        claimsSetBuilder.jwtID(UUID.randomUUID().toString());
        //TODO: check setting audience

        if (claimsRetriever != null) {

            //check in local cache
            String[] requestedClaims = messageContext.getRequestDTO().getRequiredClaimURIs();
            if (requestedClaims == null && isExistingUser) {
                // if no claims were requested, return all
                requestedClaims = claimsRetriever.getDefaultClaims(authzUser);
            }

            ClaimCacheKey cacheKey = null;
            UserClaims userClaimsFromCache = null;

            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
            authenticatedUser.setUserName(UserCoreUtil.removeDomainFromName(tenantAwareUsername));
            authenticatedUser.setUserStoreDomain(IdentityUtil.extractDomainFromName(tenantAwareUsername));
            authenticatedUser.setTenantDomain(tenantDomain);

            if (requestedClaims != null && requestedClaims.length > 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Processing " + requestedClaims.length + " requested claims for user in tenant: " +
                            tenantDomain);
                }
                cacheKey = new ClaimCacheKey(authenticatedUser);
                userClaimsFromCache = claimsLocalCache.getValueFromCache(cacheKey, tenantDomain);
            }

            SortedMap<String, String> claimValues = null;
            if (userClaimsFromCache != null) {
                // Retain only requested claims from the cache; fetch any requested claims missing from the cache
                // using claimsRetriever and update the cache with newly obtained values.
                claimValues = filterClaimsFromCache(authenticatedUser, cacheKey, tenantDomain, authzUser,
                        requestedClaims, userClaimsFromCache, isExistingUser);
            } else if (isExistingUser) {
                claimValues = claimsRetriever.getClaims(authzUser, requestedClaims);
                updateClaimCache(authenticatedUser, claimValues, cacheKey, tenantDomain);
            }

            if (isExistingUser) {
                String claimSeparator = getMultiAttributeSeparator(authzUser, tenantId);
                if (StringUtils.isNotBlank(claimSeparator)) {
                    userAttributeSeparator = claimSeparator;
                }
            }

            if (claimValues != null) {
                for (String claimURI : new TreeSet<>(claimValues.keySet())) {
                    String claimVal = claimValues.get(claimURI);
                    List<String> claimList = new ArrayList<>();
                    if (useMultiValueSeparator && userAttributeSeparator != null &&
                            claimVal.contains(userAttributeSeparator)) {
                        StringTokenizer st = new StringTokenizer(claimVal, userAttributeSeparator);
                        while (st.hasMoreElements()) {
                            String attValue = st.nextElement().toString();
                            if (StringUtils.isNotBlank(attValue)) {
                                claimList.add(attValue);
                            }
                        }
                        claimsSetBuilder.claim(claimURI, claimList.toArray(new String[claimList.size()]));
                    } else {
                        claimsSetBuilder.claim(claimURI, claimVal);
                    }
                }
            }
        }

        JWTClaimsSet claimsSet = claimsSetBuilder.build();
        JWT jwt = null;
        if (!JWSAlgorithm.NONE.equals(signatureAlgorithm)) {
            jwt = OAuth2Util.signJWT(claimsSet, signatureAlgorithm, tenantDomain);
        } else {
            jwt = new PlainJWT(claimsSet);
        }

        if (log.isDebugEnabled()) {
            log.debug("JWT Assertion Value : " + jwt.serialize());
        }
        OAuth2TokenValidationResponseDTO.AuthorizationContextToken token;
        token = messageContext.getResponseDTO().new AuthorizationContextToken("JWT", jwt.serialize());
        messageContext.getResponseDTO().setAuthorizationContextToken(token);
    }

    private SortedMap<String, String> filterClaimsFromCache(AuthenticatedUser authenticatedUser, ClaimCacheKey cacheKey,
                                                            String tenantDomain, String authzUser,
                                                            String[] requestedClaims,
                                                            UserClaims userClaimsCache, boolean isExistingUser)
            throws IdentityOAuth2Exception {

        SortedMap<String, String> cachedClaims = userClaimsCache.getClaimValues();
        Set<String> requestedSet = new LinkedHashSet<>(Arrays.asList(requestedClaims));
        SortedMap<String, String> filtered = new TreeMap<>();

        // Filter only the requested claims from the cached claims.
        for (String req : requestedSet) {
            if (cachedClaims.containsKey(req)) {
                filtered.put(req, cachedClaims.get(req));
            }
        }

        // Identify missing requested claims and try to fetch them from claimsRetriever.
        List<String> missing = new ArrayList<>();
        for (String req : requestedSet) {
            if (!filtered.containsKey(req)) {
                missing.add(req);
            }
        }
        if (!missing.isEmpty() && isExistingUser) {
            if (log.isDebugEnabled()) {
                log.debug("Fetching " + missing.size() + " missing claims from claims retriever for user: " + authzUser);
            }
            SortedMap<String, String> fetched = claimsRetriever.getClaims(authzUser,
                    missing.toArray(new String[0]));
            if (fetched != null) {
                for (Map.Entry<String, String> e : fetched.entrySet()) {
                    if (requestedSet.contains(e.getKey())) {
                        filtered.put(e.getKey(), e.getValue());
                    }
                }
            }
            // Update cache with the newly obtained claims (if any)
            if (!filtered.isEmpty()) {
                updateClaimCache(authenticatedUser, filtered, cacheKey, tenantDomain);
            }
        }

        return filtered;
    }

    private void updateClaimCache(AuthenticatedUser authenticatedUser, SortedMap<String, String> claimValues,
                                  ClaimCacheKey cacheKey, String tenantDomain) {

        if (!claimValues.isEmpty()) {
            UserClaims userClaims = new UserClaims(claimValues);
            claimsLocalCache.addToCache(cacheKey, userClaims, tenantDomain);
            ClaimMetaDataCache.getInstance().addToCache(new ClaimMetaDataCacheKey(authenticatedUser),
                    new ClaimMetaDataCacheEntry(cacheKey), tenantDomain);
        }
    }

    /**
     * Sign with given RSA Algorithm
     *
     * @param signedJWT
     * @param jwsAlgorithm
     * @param tenantDomain
     * @param tenantId
     * @return
     * @throws IdentityOAuth2Exception
     */
    @Deprecated
    protected SignedJWT signJWTWithRSA(SignedJWT signedJWT, JWSAlgorithm jwsAlgorithm, String tenantDomain,
                                       int tenantId)
            throws IdentityOAuth2Exception {
        try {
            if (tenantDomain == null) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }
            Key privateKey = IdentityKeyStoreResolver.getInstance().getPrivateKey(tenantDomain,
                    IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH);
            JWSSigner signer = OAuth2Util.createJWSSigner((RSAPrivateKey) privateKey);
            signedJWT.sign(signer);
            return signedJWT;
        } catch (JOSEException e) {
            log.error("Error in obtaining tenant's keystore", e);
            throw new IdentityOAuth2Exception("Error in obtaining tenant's keystore", e);
        } catch (Exception e) {
            log.error("Error in obtaining tenant's keystore", e);
            throw new IdentityOAuth2Exception("Error in obtaining tenant's keystore", e);
        }
    }

    /**
     * Generic Signing function
     *
     * @param signedJWT
     * @param tenantDomain
     * @param tenantId
     * @return
     * @throws IdentityOAuth2Exception
     */
    @Deprecated
    protected JWT signJWT(SignedJWT signedJWT, String tenantDomain, int tenantId)
            throws IdentityOAuth2Exception {
        if (JWSAlgorithm.RS256.equals(signatureAlgorithm) || JWSAlgorithm.RS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.RS512.equals(signatureAlgorithm)) {
            return signJWTWithRSA(signedJWT, signatureAlgorithm, tenantDomain, tenantId);
        } else if (JWSAlgorithm.HS256.equals(signatureAlgorithm) ||
                JWSAlgorithm.HS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.HS512.equals(signatureAlgorithm)) {
            // return signWithHMAC(payLoad,jwsAlgorithm,tenantDomain,tenantId); implementation
            // need to be done
        } else if (JWSAlgorithm.ES256.equals(signatureAlgorithm) ||
                JWSAlgorithm.ES384.equals(signatureAlgorithm) ||
                JWSAlgorithm.ES512.equals(signatureAlgorithm)) {
            // return signWithEC(payLoad,jwsAlgorithm,tenantDomain,tenantId); implementation
            // need to be done
        }
        log.error("UnSupported Signature Algorithm");
        throw new IdentityOAuth2Exception("UnSupported Signature Algorithm");
    }

    /**
     * This method map signature algorithm define in identity.xml to nimbus
     * signature algorithm
     * format, Strings are defined inline hence there are not being used any
     * where
     *
     * @param signatureAlgorithm
     * @return
     * @throws IdentityOAuth2Exception
     */
    @Deprecated
    protected JWSAlgorithm mapSignatureAlgorithm(String signatureAlgorithm)
            throws IdentityOAuth2Exception {
        return OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(signatureAlgorithm);
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

    /**
     * Helper method to hexify a byte array.
     * TODO:need to verify the logic
     *
     * @param bytes
     * @return hexadecimal representation
     */
    private String hexify(byte bytes[]) {

        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        StringBuilder buf = new StringBuilder(bytes.length * 2);

        for (int i = 0; i < bytes.length; ++i) {
            buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
            buf.append(hexDigits[bytes[i] & 0x0f]);
        }

        return buf.toString();
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
                claimSeparator =
                        realmConfiguration.getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
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

    private SignedJWT getSignedJWT(String tokenIdentifier) throws ParseException {
        return SignedJWT.parse(tokenIdentifier);
    }
}
