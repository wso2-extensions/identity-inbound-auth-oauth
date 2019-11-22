
package org.wso2.carbon.identity.oauth.ciba.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceDataHolder;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;

import java.sql.Timestamp;
import java.util.Calendar;
import java.util.TimeZone;
import java.util.UUID;

/**
 * Provides utilities for the functioning of other classes.
 */
public class CibaAuthUtil {

    private static final Log log = LogFactory.getLog(CibaAuthUtil.class);

    /**
     * Returns a unique AuthCodeDOKey.
     *
     * @return String Returns random uuid.
     */
    private static String getUniqueAuthCodeKey() {

        UUID id = UUID.randomUUID();
        return id.toString();
    }

    /**
     * Returns a unique auth_req_id.
     *
     * @return String Returns random uuid.
     */
    private static String getAuthReqID() {

        UUID id = UUID.randomUUID();
        return id.toString();
    }

    /**
     * Process and return the expires_in for auth_req_id.
     *
     * @param cibaAuthResponseDTO DTO accumulating validated parameters from CibaAuthenticationRequest.
     * @return long Returns expiry_time of the auth-req_id.
     */
    public static long getExpiresIn(CibaAuthResponseDTO cibaAuthResponseDTO) {

        if (cibaAuthResponseDTO.getRequestedExpiry() == 0) {
            return CibaConstants.EXPIRES_IN_DEFAULT_VALUE_IN_SEC;
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
            throw new CibaCoreException("Error in checking whether user exists.", e);
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

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        long issuedTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
        long lastPolledTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
        Timestamp issuedTime = new Timestamp(issuedTimeInMillis);
        Timestamp lastPolledTime = new Timestamp(lastPolledTimeInMillis);
        log.info(" issued time at UTC millisec : " + issuedTimeInMillis);
        log.info("issued time stamp" + issuedTime);
        long expiryTime = cibaAuthResponseDTO.getExpiredTime();
        String[] scope = cibaAuthResponseDTO.getScope();
        cibaAuthCodeDO.setCibaAuthCodeKey(CibaAuthUtil.getUniqueAuthCodeKey());
        cibaAuthCodeDO.setAuthReqID(CibaAuthUtil.getAuthReqID());
        cibaAuthCodeDO.setConsumerAppKey(cibaAuthResponseDTO.getIssuer());
        cibaAuthCodeDO.setIssuedTime(issuedTime);
        cibaAuthCodeDO.setLastPolledTime(lastPolledTime);
        cibaAuthCodeDO.setAuthenticationStatus(AuthenticationStatus.REQUESTED);
        cibaAuthCodeDO.setInterval(CibaConstants.INTERVAL_DEFAULT_VALUE_IN_SEC);
        cibaAuthCodeDO.setExpiresIn(expiryTime);
        cibaAuthCodeDO.setScope(scope);

        if (log.isDebugEnabled()) {
            log.debug("Successful in creating AuthCodeDO with cibaAuthCode = " + cibaAuthCode);
        }
        return cibaAuthCodeDO;

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
            authzRequestDTO.setNonce(cibaAuthCodeDO.getAuthReqID());
            authzRequestDTO.setCallBackUrl(callbackUri);
            authzRequestDTO.setUser(user);
            authzRequestDTO.setClient_id(clientID);
            authzRequestDTO.setScope(OAuth2Util.buildScopeString(cibaAuthResponseDTO.getScope()));

            if (log.isDebugEnabled()) {
                log.debug("Successful in creating AuthorizeRequestDTO for the client : " + clientID);
            }
            return authzRequestDTO;
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new CibaCoreException("Error in creating AuthorizeRequestDTO ", e);
        }
    }

    /**
     * Persist scopes.
     *
     * @param cibaAuthCodeDO DO with information regarding authenticationRequest.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void pesistScopes(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        CibaDAOFactory.getInstance().getCibaAuthMgtDAO().storeScope(cibaAuthCodeDO);
    }

    /**
     * Persist cibaAuthCode
     *
     * @param cibaAuthCodeDO DO with information regarding authenticationRequest.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void persistCibaAuthCode(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        CibaDAOFactory.getInstance().getCibaAuthMgtDAO().persistCibaAuthCode(cibaAuthCodeDO);
    }
}
