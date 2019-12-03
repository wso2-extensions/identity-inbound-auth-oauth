package org.wso2.carbon.identity.oauth2.device.api;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;

/**
 * Service layer to talk with DAO.
 */
public class DeviceAuthService {

    /**
     * Store device flow parameters and scopes in diffrent tables.
     *
     * @param deviceCode Code that is used to identify the device.
     * @param userCode   Code that is used to correlate two devices.
     * @param clientId   Consumer key of the application.
     * @param scope      Requested scopes.
     * @throws IdentityOAuth2Exception Error while storing device flow parameters.
     */
    public void generateDeviceResponse(String deviceCode, String userCode, String clientId, String scope)
            throws IdentityOAuth2Exception {

        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().insertDeviceFlowParameters(deviceCode,
                userCode, clientId, Constants.EXPIRES_IN_VALUE, Constants.INTERVAL_VALUE, scope);
    }

    /**
     * Store scopes in a different table.
     *
     * @param userCode Code that is used to correlate two devices.
     * @throws IdentityOAuth2Exception Error while storing scopes.
     */
    public void setAuthenticationStatus(String userCode) throws IdentityOAuth2Exception {

        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().setAuthenticationStatus(userCode,
                Constants.USED);
    }

    /**
     * Insert redirect uri to the database.
     *
     * @param clientId Consumer key of the application.
     * @param redirectURI Redirection uri of the application.
     * @throws IdentityOAuth2Exception Error while storing redirect uri.
     */
    public void setCallbackUri(String clientId, String redirectURI) throws IdentityOAuth2Exception {

        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().setCallBackURI(clientId, redirectURI);
    }

    /**
     * Get client id for user code.
     * @param userCode Code that is used to correlate two devices.
     * @return client id
     * @throws IdentityOAuth2Exception Error while getting client id for user code.
     */
    public String getClientId(String userCode) throws IdentityOAuth2Exception {
        return DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().getClientIdByUserCode(userCode);
    }

    /**
     * Get scopes for user code.
     * @param userCode Code that is used to correlate two devices.
     * @return scopes
     * @throws IdentityOAuth2Exception Error while getting scopes for user code.
     */
    public String[] getScope(String userCode) throws IdentityOAuth2Exception {
        return DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().getScopesForUserCode(userCode);
    }

    /**
     * Get status of the user code.
     * @param userCode Code that is used to correlate two devices.
     * @return status of the user code.
     * @throws IdentityOAuth2Exception Error while getting the status.
     */
    public String getStatus(String userCode) throws IdentityOAuth2Exception {
        return DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().getStatusForUserCode(userCode);
    }

    /**
     * Validate client id.
     * @param clientId Consumer key of the application.
     * @return true or false.
     * @throws IdentityOAuth2Exception Error while validate the client id.
     */
    public boolean validateClientInfo(String clientId) throws IdentityOAuth2Exception {
        return DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().checkClientIdExist(clientId);
    }
}
