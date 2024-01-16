package org.wso2.carbon.identity.oauth.dcr.model;

/**
 * DCR Configuration model.
 */
public class DCRConfiguration {

    private boolean isDCRFAPIEnforced;
    private boolean clientAuthenticationRequired;
    private String ssaJwks;

    public boolean isFAPIEnforced() {

        return isDCRFAPIEnforced;
    }

    public void setFAPIEnforced(boolean isDCRFAPIEnforced) {
        this.isDCRFAPIEnforced = isDCRFAPIEnforced;
    }

    public boolean isClientAuthenticationRequired() {
        return clientAuthenticationRequired;
    }

    public void setClientAuthenticationRequired(boolean clientAuthenticationRequired) {
        this.clientAuthenticationRequired = clientAuthenticationRequired;
    }

    public String getSsaJwks() {
        return ssaJwks;
    }

    public void setSsaJwks(String ssaJwks) {
        this.ssaJwks = ssaJwks;
    }
}
