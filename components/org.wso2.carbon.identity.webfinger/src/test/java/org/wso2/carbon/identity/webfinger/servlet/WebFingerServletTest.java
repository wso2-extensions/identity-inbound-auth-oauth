package org.wso2.carbon.identity.webfinger.servlet;

import org.apache.commons.collections.iterators.IteratorEnumeration;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.webfinger.DefaultWebFingerProcessor;
import org.wso2.carbon.identity.webfinger.internal.WebFingerServiceComponentHolder;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

;

/**
 * Tests web-finger servlet.
 */
public class WebFingerServletTest {

    @BeforeClass
    protected void setUp() {
        WebFingerServiceComponentHolder.setWebFingerProcessor(DefaultWebFingerProcessor.getInstance());
    }

    @Test
    public void testDoGet() throws Exception {
        final Map<String, String> parameters = new HashMap<>();

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getParameterNames()).thenReturn(new IteratorEnumeration(parameters.keySet().iterator()));
        Mockito.when(request.getParameter(Matchers.anyString())).thenAnswer(new Answer<String>() {

            @Override
            public String answer(InvocationOnMock invocationOnMock) throws Throwable {
                return parameters.get(invocationOnMock.getArgumentAt(0, String.class));
            }
        });

        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        
        Mockito.doAnswer(new Answer() {

            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                return null;
            }
        }).when(response).setStatus(Matchers.anyInt());

        WebFingerServlet webFingerServlet = new WebFingerServlet();
        webFingerServlet.doGet(request, response);
    }

    @Test
    public void testGetOIDProviderIssuer() throws Exception {
    }

}
