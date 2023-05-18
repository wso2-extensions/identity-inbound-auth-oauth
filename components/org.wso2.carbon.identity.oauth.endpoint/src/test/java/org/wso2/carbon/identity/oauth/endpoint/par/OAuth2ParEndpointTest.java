package org.wso2.carbon.identity.oauth.endpoint.par;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.ciba.OAuth2CibaEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.exception.ParErrorDTO;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({OAuth2Util.class, OAuthServerConfiguration.class, EndpointUtil.class, LogFactory.class,
        HttpServletRequest.class, HttpServletResponse.class})
public class OAuth2ParEndpointTest extends Mockito {

    private static final String ERROR = "error";
    private static final String ERROR_DESCRIPTION = "error_description";

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @InjectMocks
    private OAuth2ParEndpoint oAuth2ParEndpoint;

    @Before
    public void setUp() throws Exception {
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );

        oAuth2ParEndpoint = new OAuth2ParEndpoint();
    }

    @Test
    public void testParForProperRequest() throws Exception, ParErrorDTO {

        Map<String, String[]> requestParams = new HashMap<>();
        requestParams.put(OAuthConstants.OAuth20Params.CLIENT_ID, new String[]{"7iGW7YHEAVlniHXb4lAKqYBLAk4a"});
        requestParams.put(OAuthConstants.OAuth20Params.REDIRECT_URI, new String[]{"http://localhost:8080/playground2"});
        requestParams.put(OAuthConstants.OAuth20Params.RESPONSE_TYPE, new String[]{"code"});
        requestParams.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{"email"});

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(httpServletRequest.getParameterMap()).thenReturn(requestParams);

        //Response response = oAuth2ParEndpoint.par(httpServletRequest, httpServletResponse);
        //Assert.assertEquals(201, response.getStatus());
    }
}

