package org.wso2.carbon.identity.oauth2.device.api;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;

public class DeviceAuthService {

    public void generateDeviceResponse(String deviceCode, String userCode, String clientId, String scope)
            throws IdentityOAuth2Exception {

        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().insertDeviceFlowParameters(deviceCode,
                userCode, clientId, Constants.EXPIRES_IN_VALUE, Constants.INTERVAL_VALUE);
        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().storeDeviceFlowScopes(scope, deviceCode);
    }

    public void setAuthenticationStatus(String userCode) throws IdentityOAuth2Exception {
        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().setAuthenticationStatus(userCode,
                Constants.USED);
    }
}
