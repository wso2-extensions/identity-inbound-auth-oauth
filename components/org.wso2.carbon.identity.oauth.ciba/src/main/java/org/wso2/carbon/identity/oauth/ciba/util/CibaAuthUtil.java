
package org.wso2.carbon.identity.oauth.ciba.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceDataHolder;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.util.UUID;
import javax.servlet.http.HttpServletResponse;

/**
 * Provides utilities for the functioning of other classes.
 */

public class CibaAuthUtil {

    private static final Log log = LogFactory.getLog(CibaAuthUtil.class);

    /**
     * Create and returns ciba auth_req_id as a JWT.
     *
     * @param cibaAuthResponseDTO which is infiltrated with validated parameters from authRequestDTO.
     * @return JWT CibaAuthCode which will have necessary claims for auth_req_id.
     * @throws CibaCoreException Exception thrown at CibaCoreComponent.
     */
    public static JWT getCibaAuthReqIDasSignedJWT(CibaAuthResponseDTO cibaAuthResponseDTO) throws CibaCoreException {

        String clientId = cibaAuthResponseDTO.getAudience();
        try {
            JWTClaimsSet requestClaims = buildJWT(cibaAuthResponseDTO);

            String tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(clientId);

            // Sign the auth_req_id.
            JWT JWTStringAsAuthReqID = OAuth2Util.signJWT(requestClaims, JWSAlgorithm.RS256, tenantDomain);
            // Using recommended algorithm by FAPI [PS256,ES256 also  can be used]

            if (log.isDebugEnabled()) {
                log.debug("Returning CibaAuthCode for the request made by client : " + clientId);
            }
            return JWTStringAsAuthReqID;

        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error in building and returning CibaAuthCode for the request made by client : " + clientId);
            }
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }

    /**
     * Create and returns CIBA auth_req_id claims.
     *
     * @param cibaAuthResponseDTO Contains the validated parameters from the ciba authentication request.
     * @return JWTClaimsSet Returns JWT.
     */
    private static JWTClaimsSet buildJWT(CibaAuthResponseDTO cibaAuthResponseDTO) {

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience(cibaAuthResponseDTO.getAudience())
                .issuer(cibaAuthResponseDTO.getIssuer())
                .jwtID(cibaAuthResponseDTO.getJWTID())
                .claim(CibaParams.USER_HINT, cibaAuthResponseDTO.getUserHint())
                .claim("exp", cibaAuthResponseDTO.getExpiredTime())
                .claim("iat", cibaAuthResponseDTO.getIssuedTime())
                .claim("nbf", cibaAuthResponseDTO.getNotBeforeTime())
                .claim(CibaParams.SCOPE, OAuth2Util.buildScopeString(cibaAuthResponseDTO.getScope()))
                .claim(CibaParams.ACR_VALUES, cibaAuthResponseDTO.getAcrValues())
                .claim(CibaParams.USER_CODE, cibaAuthResponseDTO.getUserCode())
                .claim(CibaParams.BINDING_MESSAGE, cibaAuthResponseDTO.getBindingMessage())
                .claim(CibaParams.TRANSACTION_CONTEXT, cibaAuthResponseDTO.getTransactionContext())
                .build();

        if (log.isDebugEnabled()) {
            log.debug("Successfully created JWT from CibaAuthResponseDTO and returning in regard to the   " +
                    "the request made by client " + cibaAuthResponseDTO.getAudience());
        }

        return claims;

    }

    /**
     * Transfers validated values of AuthenticationRequestDTO to AuthenticationResponseDTO.
     *
     * @param cibaAuthRequestDTO Ciba Authentication Request DTO.
     * @return CibaAuthResponseDTO Returns JWT.
     */
    public static CibaAuthResponseDTO buildCibaAuthResponseDTO(CibaAuthRequestDTO cibaAuthRequestDTO) {

        CibaAuthResponseDTO cibaAuthResponseDTO = new CibaAuthResponseDTO();

        long issuedTime = ZonedDateTime.now().toInstant().toEpochMilli();
        long durability = getExpiresIn(cibaAuthRequestDTO) * 1000;
        long expiryTime = issuedTime + durability;
        long notBeforeUsable = issuedTime + CibaParams.INTERVAL_DEFAULT_VALUE * 1000;

        cibaAuthResponseDTO.setIssuer(cibaAuthRequestDTO.getAudience());
        cibaAuthResponseDTO.setAudience(cibaAuthRequestDTO.getIssuer());
        cibaAuthResponseDTO.setJWTID(getUniqueAuthCodeDOKey());
        cibaAuthResponseDTO.setUserHint(cibaAuthRequestDTO.getUserHint());
        cibaAuthResponseDTO.setExpiredTime(expiryTime);
        cibaAuthResponseDTO.setIssuedTime(issuedTime);
        cibaAuthResponseDTO.setNotBeforeTime(notBeforeUsable);
        cibaAuthResponseDTO.setScope(cibaAuthRequestDTO.getScope());
        cibaAuthResponseDTO.setAcrValues(cibaAuthRequestDTO.getAcrValues());
        cibaAuthResponseDTO.setUserCode(cibaAuthRequestDTO.getUserCode());
        cibaAuthResponseDTO.setBindingMessage(cibaAuthRequestDTO.getBindingMessage());
        cibaAuthResponseDTO.setTransactionContext(cibaAuthRequestDTO.getTransactionContext());

        if (log.isDebugEnabled()) {
            log.debug("Successfully transferred validated values from CIbaAuthRequestDTO to CibaAuthResponseDTO and " +
                    "for the  request made by client : " + cibaAuthResponseDTO.getAudience());
        }

        return cibaAuthResponseDTO;
    }

    /**
     * Returns a unique AuthCodeDOKey.
     *
     * @return String Returns random uuid.
     */
    private static String getUniqueAuthCodeDOKey() {

        UUID id = UUID.randomUUID();
        return id.toString();

    }

    /**
     * Returns a random id.
     *
     * @return String Returns random uuid.
     */
    public static String getUniqueID() {

        UUID uuid = UUID.randomUUID();
        return uuid.toString();

    }

    /**
     * Create hash of the provided auth_req_id.
     *
     * @param JWTStringAsAuthReqID auth_req_id.
     * @return String Hashed auth_req_id.
     */
    public static String createHash(String JWTStringAsAuthReqID) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        // getInstance() method is called with algorithm SHA-512

        // digest() method is called.
        // To calculate message digest of the input string.
        // Returned as array of byte.
        byte[] messageDigest = md.digest(JWTStringAsAuthReqID.getBytes());

        // Convert byte array into signum representation.
        BigInteger no = new BigInteger(1, messageDigest);

        // Convert message digest into hex value.
        String hashtext = no.toString(16);

        // Add preceding 0s to make it 32 bit.
        while (hashtext.length() < 32) {
            hashtext = "0" + hashtext;
        }

        // Return the HashText.
        return hashtext;
    }

    /**
     * Process and return the expires_in for auth_req_id.
     *
     * @param cibaAuthRequestDTO DTO accumulating validated parameters from CibaAuthenticationRequest.
     * @return long Returns expiry_time of the auth-req_id.
     */
    public static long getExpiresIn(CibaAuthRequestDTO cibaAuthRequestDTO) {

        if (cibaAuthRequestDTO.getRequestedExpiry() == 0) {
            return CibaParams.EXPIRES_IN_DEFAULT_VALUE;
        } else {
            return cibaAuthRequestDTO.getRequestedExpiry();
        }
    }

    /**
     * Process and return the expires_in for auth_req_id.
     *
     * @param cibaAuthResponseDTO DTO accumulating response parameters.
     * @return long Returns expiry_time of the auth-req_id.
     */
    public static long getExpiresInForResponse(CibaAuthResponseDTO cibaAuthResponseDTO) {

        if (cibaAuthResponseDTO.getRequestedExpiry() == 0) {
            return CibaParams.EXPIRES_IN_DEFAULT_VALUE;
        } else {
            return cibaAuthResponseDTO.getRequestedExpiry();
        }
    }

    /**
     * Check whether user exists in store.
     *
     * @param tenantID   tenantID of the clientAPP
     * @param userIdHint that identifies a user
     * @return boolean Returns whether user exists in store.
     */
    public static boolean isUserExists(int tenantID, String userIdHint) throws CibaCoreException {

        try {
            return CibaServiceDataHolder.getRealmService().
                    getTenantUserRealm(tenantID).getUserStoreManager().
                    isExistingUser(userIdHint);

        } catch (UserStoreException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ErrorCodes.INTERNAL_SERVER_ERROR,
                    e.getMessage());
        }

    }

    /**
     * Builds and returns AuthorizationRequestDTO.
     *
     * @param cibaAuthCode        JWT with claims necessary for AuthCodeDO .
     * @param cibaAuthResponseDTO Status of the relevant Ciba Authentication.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public static CibaAuthCodeDO generateCibaAuthCodeDO(String cibaAuthCode, CibaAuthResponseDTO cibaAuthResponseDTO)
            throws CibaCoreException {

        try {

            long lastPolledTime = cibaAuthResponseDTO.getIssuedTime();
            long expiryTime = cibaAuthResponseDTO.getExpiredTime();

            String hashValueOfCibaAuthReqId = CibaAuthUtil.createHash(cibaAuthCode);

            String bindingMessage = cibaAuthResponseDTO.getBindingMessage();
            String transactionContext = cibaAuthResponseDTO.getTransactionContext();
            String scope = OAuth2Util.buildScopeString(cibaAuthResponseDTO.getScope());

            CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
            cibaAuthCodeDO.setCibaAuthCodeDOKey(CibaAuthUtil.getUniqueAuthCodeDOKey());
            cibaAuthCodeDO.setHashedCibaAuthReqId(hashValueOfCibaAuthReqId);
            cibaAuthCodeDO.setAuthenticationStatus(AuthenticationStatus.REQUESTED.toString());
            cibaAuthCodeDO.setLastPolledTime(lastPolledTime);
            cibaAuthCodeDO.setInterval(CibaParams.INTERVAL_DEFAULT_VALUE);
            cibaAuthCodeDO.setExpiryTime(expiryTime);
            cibaAuthCodeDO.setBindingMessage(bindingMessage);
            cibaAuthCodeDO.setTransactionContext(transactionContext);
            cibaAuthCodeDO.setScope(scope);

            if (log.isDebugEnabled()) {
                log.debug("Successful in creating AuthCodeDO with cibaAuthCode = " + cibaAuthCode);
            }

            return cibaAuthCodeDO;
        } catch (NoSuchAlgorithmException e) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to create AuthCodeDO with cibaAuthCode = " + cibaAuthCode);
            }

            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }

    /**
     * Builds and returns AuthorizationRequestDTO.
     *
     * @param cibaAuthCodeDO      DO with information regarding authenticationRequest.
     * @param cibaAuthResponseDTO Status of the relevant Ciba Authentication.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public static AuthzRequestDTO buildAuthzRequestDO(CibaAuthResponseDTO cibaAuthResponseDTO,
                                                      CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        String clientID = cibaAuthResponseDTO.getAudience();
        try {
            AuthzRequestDTO authzRequestDTO = new AuthzRequestDTO();

            String user = cibaAuthResponseDTO.getUserHint();

            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientID);

            String callbackUri = appDO.getCallbackUrl();

            authzRequestDTO.setAuthReqIDasState(cibaAuthCodeDO.getCibaAuthCodeDOKey());
            authzRequestDTO.setCallBackUrl(callbackUri);
            authzRequestDTO.setUser(user);
            authzRequestDTO.setClient_id(clientID);
            authzRequestDTO.setBindingMessage(cibaAuthCodeDO.getBindingMessage());
            authzRequestDTO.setTransactionDetails(cibaAuthCodeDO.getTransactionContext());
            authzRequestDTO.setScope(cibaAuthCodeDO.getScope());

            if (log.isDebugEnabled()) {
                log.debug("Successful in creating AuthorizeRequestDTO for the client : " + clientID);
            }
            return authzRequestDTO;

        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {

            if (log.isDebugEnabled()) {
                log.debug("Error in creating AuthorizeRequestDTO for the client : " + clientID);
            }
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

}

