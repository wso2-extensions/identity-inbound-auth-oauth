package org.wso2.carbon.identity.oauth.par.model;

import org.apache.catalina.util.ParameterMap;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class ParDataRecord implements Serializable {

    //private Map<String, String[]> params;
    private ParameterMap parameterMap;
    private long reqMade;

    public ParDataRecord(ParameterMap parameterMap , long reqMade) {
        this.parameterMap = parameterMap;
        this.reqMade = reqMade;
    }

    public ParameterMap getParamMap() {
        return parameterMap;
    }

    public long getReqMade() {
        return reqMade;
    }
}
