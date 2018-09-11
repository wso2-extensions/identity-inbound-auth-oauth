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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
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
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.text.ParseException;

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

    private final static String JWT_TOKEN_TYPE = "JWT";

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
                signatureAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(sigAlg);
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
        //TODO: check setting audience



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
                        claimsSetBuilder.claim(claimURI, claimList.toArray(new String[claimList.size()]));
                    } else {
                        claimsSetBuilder.claim(claimURI, claimVal);
                    }
                }
            }
        }

        JWTClaimsSet claimsSet = claimsSetBuilder.build();
        JWT jwt = null;
        if(!JWSAlgorithm.NONE.equals(signatureAlgorithm)){
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
            Key privateKey = getPrivateKey(tenantDomain, tenantId);
            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
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
     * Helper method to add public certificate to JWT_HEADER to signature verification.
     *
     * @param tenantDomain
     * @param tenantId
     * @throws IdentityOAuth2Exception
     */
    private String getThumbPrint(String tenantDomain, int tenantId) throws IdentityOAuth2Exception {

        try {

            Certificate certificate = getCertificate(tenantDomain, tenantId);

            // TODO: maintain a hashmap with tenants' pubkey thumbprints after first initialization

            //generate the SHA-1 thumbprint of the certificate
            MessageDigest digestValue = MessageDigest.getInstance("SHA-1");
            byte[] der = certificate.getEncoded();
            digestValue.update(der);
            byte[] digestInBytes = digestValue.digest();

            String publicCertThumbprint = hexify(digestInBytes);
            String base64EncodedThumbPrint = new String(new Base64(0, null, true).encode(publicCertThumbprint
                    .getBytes(Charsets.UTF_8)), Charsets.UTF_8);
            return base64EncodedThumbPrint;

        } catch (Exception e) {
            String error = "Error in obtaining certificate for tenant " + tenantDomain;
            throw new IdentityOAuth2Exception(error, e);
        }
    }

    private Key getPrivateKey(String tenantDomain, int tenantId) throws IdentityOAuth2Exception {

        if (tenantDomain == null) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        if (tenantId == 0) {
            tenantId = OAuth2Util.getTenantId(tenantDomain);
        }

        Key privateKey = null;

        if (!(privateKeys.containsKey(tenantId))) {

            try {
                IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
            } catch (IdentityException e) {
                throw new IdentityOAuth2Exception("Error occurred while loading registry for tenant " + tenantDomain, e);
            }

            // get tenant's key store manager
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                // derive key store name
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                // obtain private key
                privateKey = tenantKSM.getPrivateKey(jksName, tenantDomain);

            } else {
                try {
                    privateKey = tenantKSM.getDefaultPrivateKey();
                } catch (Exception e) {
                    log.error("Error while obtaining private key for super tenant", e);
                }
            }
            if (privateKey != null) {
                privateKeys.put(tenantId, privateKey);
            }
        } else {
            privateKey = privateKeys.get(tenantId);
        }
        return privateKey;
    }

    private Certificate getCertificate(String tenantDomain, int tenantId) throws Exception {

        if (tenantDomain == null) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        if (tenantId == 0) {
            tenantId = OAuth2Util.getTenantId(tenantDomain);
        }

        Certificate publicCert = null;

        if (!(publicCerts.containsKey(tenantId))) {

            try {
                IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
            } catch (IdentityException e) {
                throw new IdentityOAuth2Exception("Error occurred while loading registry for tenant " + tenantDomain, e);
            }

            // get tenant's key store manager
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

            KeyStore keyStore = null;
            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                // derive key store name
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                keyStore = tenantKSM.getKeyStore(jksName);
                publicCert = keyStore.getCertificate(tenantDomain);
            } else {
                publicCert = tenantKSM.getDefaultPrimaryCertificate();
            }
            if (publicCert != null) {
                publicCerts.put(tenantId, publicCert);
            }
        } else {
            publicCert = publicCerts.get(tenantId);
        }
        return publicCert;
    }

    /**
     * Helper method to hexify a byte array.
     * TODO:need to verify the logic
     *
     * @param bytes
     * @return  hexadecimal representation
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

    private SignedJWT getSignedJWT(String tokenIdentifier) throws ParseException {
        return SignedJWT.parse(tokenIdentifier);
    }
}
