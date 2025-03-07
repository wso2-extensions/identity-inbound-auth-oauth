package org.wso2.carbon.identity.oauth.endpoint;

public class OAuthResponseWrapper {
    private Object response;

    public OAuthResponseWrapper(Object response) {
        this.response = response;
    }

    public Object getResponse() {
        return response;
    }

    public void setResponse(Object response) {
        this.response = response;
    }
}

