package org.wso2.carbon.identity.oauth2.device.model;

import org.wso2.carbon.identity.oauth.cache.CacheEntry;

import java.sql.Timestamp;

public class DeviceFlowDO extends CacheEntry {

    private String deviceCode;

    private String userCode;

    private String consumerKeyID;

    private String[] scope;

    private Timestamp issuedTime;

    private Timestamp expiredTime;

    private String Status;

    private Timestamp lastPollTime;

    public DeviceFlowDO() {

    }

    public String getDeviceCode() {

        return deviceCode;
    }

    public void setDeviceCode(String deviceCode) {

        this.deviceCode = deviceCode;
    }

    public String getUserCode() {

        return userCode;
    }

    public void setUserCode(String userCode) {

        this.userCode = userCode;
    }

    public String getConsumerKeyID() {

        return consumerKeyID;
    }

    public void setConsumerKeyID(String consumerKeyID) {

        this.consumerKeyID = consumerKeyID;
    }

    public String[] getScope() {

        return scope;
    }

    public void setScope(String[] scope) {

        this.scope = scope;
    }

    public Timestamp getIssuedTime() {

        return issuedTime;
    }

    public void setIssuedTime(Timestamp issuedTime) {

        this.issuedTime = issuedTime;
    }

    public Timestamp getExpiredTime() {

        return expiredTime;
    }

    public void setExpiredTime(Timestamp expiredTime) {

        this.expiredTime = expiredTime;
    }

    public String getStatus() {

        return Status;
    }

    public void setStatus(String status) {

        Status = status;
    }

    public void setLastPollTime(Timestamp lastPollTime) {

        this.lastPollTime = lastPollTime;
    }

    public Timestamp getLastPollTime() {

        return lastPollTime;
    }

}
