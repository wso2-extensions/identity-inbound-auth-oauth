package org.wso2.carbon.identity.oauth.par.model;

import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;

public class ParDataRecord implements Serializable {

    private OAuthAuthzRequest parAuthRequest;
    private long reqMade;

    public ParDataRecord(OAuthAuthzRequest parAuthRequest, long reqMade) {
        this.parAuthRequest = parAuthRequest;
        this.reqMade = reqMade;
    }

    public OAuthAuthzRequest getParAuthRequest() {
        return parAuthRequest;
    }

    public long getReqMade() {
        return reqMade;
    }
}
