package org.wso2.carbon.identity.oauth.endpoint.par;

import org.apache.catalina.util.ParameterMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.HashMap;
import java.util.Map;

public class OAuthParRequestWrapper extends HttpServletRequestWrapper {

    HashMap<String, String> params = new HashMap<>();

    public OAuthParRequestWrapper(HttpServletRequest request) throws Exception {
        super(request);

        // Get request data from PAR and add tp params
        String uuid = request.getRequestURI().substring(request.getRequestURI().length() - 36);
        String requestUri = request.getRequestURI();
        System.out.println("request_uri: " + requestUri);
        //HashMap<String, String> paramMapHashMap = ParRequestData.getRequests().get(requestUri); // get the parameterMap for given request_uri
        //System.out.println("paramMap from AuthEndpoint (HashMap): \n" + paramMapHashMap + "\nend\n");
        params = DataRecordWriter.readRecord(uuid).getParamMap(); //get data from Database
        System.out.println("paramMap from AuthEndpoint (Database): \n" + params + "\nend\n");
    }

    @Override
    public String getParameter(String name) {

        if (params.containsKey(name)) {
            return params.get(name);
        }

        return super.getParameter(name);
    }
}
