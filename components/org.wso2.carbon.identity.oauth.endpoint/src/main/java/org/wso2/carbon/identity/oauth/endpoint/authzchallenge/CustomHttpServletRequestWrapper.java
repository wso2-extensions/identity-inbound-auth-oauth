package org.wso2.carbon.identity.oauth.endpoint.authzchallenge;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.HashMap;
import java.util.Map;

public class CustomHttpServletRequestWrapper extends HttpServletRequestWrapper {
    private final Map<String, String[]> additionalParams;

    public CustomHttpServletRequestWrapper(HttpServletRequest request, String key, String value) {
        super(request);
        additionalParams = new HashMap<>(request.getParameterMap());
        additionalParams.put(key, new String[]{value});
    }

    @Override
    public String getParameter(String name) {
        return additionalParams.containsKey(name) ? additionalParams.get(name)[0] : super.getParameter(name);
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        return additionalParams;
    }

    @Override
    public String[] getParameterValues(String name) {
        return additionalParams.getOrDefault(name, super.getParameterValues(name));
    }
}
