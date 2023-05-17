package org.wso2.carbon.identity.oauth.par.model;

/**
 * Captures the values for response given by PAR Endpoint.
 */
public class ParAuthResponseData {

    private String uuid;
    private long expityTime;

    public String getUuid() {
        return uuid;
    }

    public long getExpityTime() {
        return expityTime;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public void setExpityTime(long expityTime) {
        this.expityTime = expityTime;
    }
}
