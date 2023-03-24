package org.wso2.carbon.identity.oauth.par.model;

import org.apache.catalina.util.ParameterMap;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class ParDataRecord implements Serializable {
    private HashMap<String, String> parameterMap;
    private long reqMade;

    public ParDataRecord(HashMap<String, String> parameterMap , long reqMade) {
        this.parameterMap = parameterMap;
        this.reqMade = reqMade;
    }

    public HashMap<String, String> getParamMap() {
        return parameterMap;
    }

    public long getReqMade() {
        return reqMade;
    }
}
