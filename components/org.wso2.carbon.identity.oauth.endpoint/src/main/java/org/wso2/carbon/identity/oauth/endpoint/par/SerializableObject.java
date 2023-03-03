package org.wso2.carbon.identity.oauth.endpoint.par;

import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;

import java.io.Serializable;

public class SerializableObject implements Serializable {

    private Object oAuthAuthzRequest;

    public SerializableObject(Object oAuthAuthzRequest) {
        this.oAuthAuthzRequest = oAuthAuthzRequest;
    }

    public Object getoAuthAuthzRequest() {
        return oAuthAuthzRequest;
    }

    public void setoAuthAuthzRequest(Object oAuthAuthzRequest) {
        this.oAuthAuthzRequest = oAuthAuthzRequest;
    }
}
