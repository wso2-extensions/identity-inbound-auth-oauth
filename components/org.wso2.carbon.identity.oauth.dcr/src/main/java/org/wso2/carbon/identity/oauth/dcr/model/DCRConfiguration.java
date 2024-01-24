package org.wso2.carbon.identity.oauth.dcr.model;

/**
 * DCR Configuration model.
 */
public class DCRConfiguration {

    private Boolean isDCRFAPIEnforced;
    private Boolean clientAuthenticationRequired;
    private String ssaJwks;

    public Boolean isFAPIEnforced() {

        return isDCRFAPIEnforced;
    }

    public void setFAPIEnforced(Boolean isDCRFAPIEnforced) {
        this.isDCRFAPIEnforced = isDCRFAPIEnforced;
    }

    public Boolean isClientAuthenticationRequired() {
        return clientAuthenticationRequired;
    }

    public void setClientAuthenticationRequired(Boolean clientAuthenticationRequired) {
        this.clientAuthenticationRequired = clientAuthenticationRequired;
    }

    public String getSsaJwks() {
        return ssaJwks;
    }

    public void setSsaJwks(String ssaJwks) {
        this.ssaJwks = ssaJwks;
    }
}
