package org.wso2.carbon.identity.oauth.endpoint;

public class AuthResponseWrapper {
    private Object response;

    public AuthResponseWrapper(Object response) {
        this.response = response;
    }

    public Object getResponse() {
        return response;
    }

    public void setResponse(Object response) {
        this.response = response;
    }
}

