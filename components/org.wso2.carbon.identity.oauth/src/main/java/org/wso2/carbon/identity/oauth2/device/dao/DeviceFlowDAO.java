package org.wso2.carbon.identity.oauth2.device.dao;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.sql.Timestamp;
import java.util.HashMap;

public interface DeviceFlowDAO {

    void insertDeviceFlow(String deviceCode, String userCode, String consumerKey, String scope, Long expiresIn) throws
            IdentityOAuth2Exception;

    String getClientIdByUSerCode(String userCode) throws IdentityOAuth2Exception;

    void setUserAuthenticated(String userCode, String status) throws IdentityOAuth2Exception;

    String getClientIdByDeviceCode(String deviceCode) throws IdentityOAuth2Exception;

    HashMap getAuthenticationStatus(String deviceCode) throws IdentityOAuth2Exception;

    boolean checkClientIdExist(String clientId) throws IdentityOAuth2Exception;

    String getScopeForDevice(String userCode) throws IdentityOAuth2Exception;

    String getStatusForUserCode(String userCode) throws IdentityOAuth2Exception;

    void setLastPollTime(String deviceCode, Timestamp newPollTime) throws IdentityOAuth2Exception;

    void setAuthzUser(String userCode, String userName) throws IdentityOAuth2Exception;

    void setDeviceCodeExpired(String deviceCode, String status) throws IdentityOAuth2Exception;

}
