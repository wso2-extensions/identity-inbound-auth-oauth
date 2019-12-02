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
                userCode, clientId, Constants.EXPIRES_IN_VALUE, Constants.INTERVAL_VALUE);
        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().storeDeviceFlowScopes(scope, deviceCode);
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
}
