package org.wso2.carbon.identity.oauth2.model;

import com.hazelcast.com.fasterxml.jackson.annotation.JsonIgnore;
import com.hazelcast.com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AccessTokenExtendedAttributes implements Serializable {

    private static final long serialVersionUID = -3043225645166013281L;
    @JsonIgnore
    private boolean isExtendedToken;
    private int refreshTokenValidityPeriod;
    private Map<String, String> parameters;

    public AccessTokenExtendedAttributes() {}

    public AccessTokenExtendedAttributes(int refreshTokenValidityPeriod, Map<String, String> parameters,
                                         boolean isExtendedToken) {

        this.refreshTokenValidityPeriod = refreshTokenValidityPeriod;
        this.parameters = parameters;
    }

    public AccessTokenExtendedAttributes(int refreshTokenValidityPeriod, Map<String, String> parameters) {

        this.refreshTokenValidityPeriod = refreshTokenValidityPeriod;
        this.parameters = parameters;
    }

    public AccessTokenExtendedAttributes(Map<String, String> parameters) {

        this.isExtendedToken = true;
        this.parameters = parameters;
    }

    public int getRefreshTokenValidityPeriod() {

        return refreshTokenValidityPeriod;
    }

    public void setRefreshTokenValidityPeriod(int refreshTokenValidityPeriod) {

        this.refreshTokenValidityPeriod = refreshTokenValidityPeriod;
    }

    public Map<String, String> getParameters() {

        return parameters;
    }

    public void setParameters(Map<String, String> parameters) {

        this.parameters = parameters;
    }

    public boolean isExtendedToken() {

        return isExtendedToken;
    }

    public void setExtendedToken(boolean isExtendedToken) {

        this.isExtendedToken = isExtendedToken;
    }
}
