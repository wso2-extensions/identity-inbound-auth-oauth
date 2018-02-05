package org.wso2.carbon.identity.oauth2.token.handlers.grant.iwa.ntlm;

import com.sun.jna.platform.win32.Sspi;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.iwa.ntlm.util.SimpleHttpRequest;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import waffle.util.Base64;
import waffle.windows.auth.impl.WindowsAccountImpl;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;
import waffle.windows.auth.impl.WindowsCredentialsHandleImpl;
import waffle.windows.auth.impl.WindowsSecurityContextImpl;

import java.security.Principal;
import javax.security.auth.Subject;

import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;

@PrepareForTest({ OAuthServerConfiguration.class, WindowsAuthProviderImpl.class, WindowsAuthProviderImpl.class,
                  WindowsCredentialsHandleImpl.class, WindowsAccountImpl.class, WindowsSecurityContextImpl.class,
                  NTLMAuthenticationGrantHandler.class })

@PowerMockIgnore({ "com.google.common.cache.*" })
public class NTLMAuthenticationGrantHandlerTest extends PowerMockIdentityBaseTest {

    private static String SECURITY_PACKAGE = "Negotiate";
    private static String TOKEN = "tretertertert43t3t43t34t3t3t3";
    private static String CURRENT_USERNAME = "test\\testdomain/testuser.carbon.super";
    private static String TOKEN_STRING = " NTLM, Basic realm=\"BasicSecurityFilterProvider\"" ;
    private static String PRINCIPAL_NAME = "testPrincipal" ;

    private static String SECURITY_HEADER = "javax.security.auth.subject";


    @Mock
    private OAuthServerConfiguration serverConfiguration;
    @Mock
    private WindowsAuthProviderImpl windowsAuthProvider;
    @Mock
    private WindowsCredentialsHandleImpl windowsCredentialsHandle;
    @Mock
    private WindowsSecurityContextImpl windowsSecurityContext;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @DataProvider
    public Object[][] getValidateGrantTypeHandlerData() {
        return new Object[][] {
                { null }, { TOKEN }
        };
    }

    @BeforeMethod
    public void setUp() throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        MockitoAnnotations.initMocks(this);

        when(OAuthServerConfiguration.getInstance()).thenReturn(serverConfiguration);
    }

    @Test
    public void testIssueRefreshToken() throws Exception {
        NTLMAuthenticationGrantHandler ntlmAuthenticationGrantHandler = new NTLMAuthenticationGrantHandler();
        boolean ret = ntlmAuthenticationGrantHandler.issueRefreshToken();
        Assert.assertEquals(ret, false);
    }

    @Test(dataProvider = "getValidateGrantTypeHandlerData")
    public void testValidateGrant(String token) throws Exception {

        mockStatic(WindowsAuthProviderImpl.class);
        mockStatic(WindowsCredentialsHandleImpl.class);
        mockStatic(WindowsAccountImpl.class);



        whenNew(WindowsAuthProviderImpl.class).withAnyArguments().thenReturn(windowsAuthProvider);
        when(WindowsCredentialsHandleImpl.getCurrent(SECURITY_PACKAGE)).thenReturn(windowsCredentialsHandle);
        when(WindowsAccountImpl.getCurrentUsername()).thenReturn(CURRENT_USERNAME);

        whenNew(WindowsSecurityContextImpl.class).withAnyArguments().thenReturn(windowsSecurityContext);
        doNothing().when(windowsSecurityContext).initialize(null, null, CURRENT_USERNAME);

        Sspi.CtxtHandle ctxtHandle = new Sspi.CtxtHandle();
        when(windowsSecurityContext.getHandle()).thenReturn(ctxtHandle);
        byte[] continueTokenBytes = Base64.decode(TOKEN_STRING);
        Sspi.SecBufferDesc secBufferDesc = new Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, continueTokenBytes);
        whenNew(Sspi.SecBufferDesc.class).withArguments(Sspi.SECBUFFER_TOKEN, continueTokenBytes).thenReturn
                (secBufferDesc);
        doNothing().when(windowsSecurityContext).initialize(ctxtHandle, secBufferDesc, "localhost");
        if (token != null) {
            when(windowsSecurityContext.getToken()).thenReturn(token.getBytes());
        }

        NTLMAuthenticationGrantHandler ntlmAuthenticationGrantHandler = new NTLMAuthenticationGrantHandler();
        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setWindowsToken(token);
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = new OAuthTokenReqMessageContext(
                oAuth2AccessTokenReqDTO);

        SimpleHttpRequest simpleHttpRequest = new SimpleHttpRequest();
        whenNew(SimpleHttpRequest.class).withNoArguments().thenReturn(simpleHttpRequest);
        Subject subject = new Subject();
        subject.getPrincipals().add(new Principal() {
            @Override
            public String getName() {
                return PRINCIPAL_NAME;
            }
        });
        simpleHttpRequest.getSession().setAttribute(SECURITY_HEADER, subject);
        try {
            ntlmAuthenticationGrantHandler.validateGrant(oAuthTokenReqMessageContext);
            AuthenticatedUser authorizedUser =
                    oAuthTokenReqMessageContext.getAuthorizedUser();
            Assert.assertNotNull(authorizedUser);
            Assert.assertNotNull(authorizedUser.getUserName(), CURRENT_USERNAME);
        } catch (IdentityOAuth2Exception e) {
            Assert.assertEquals(e.getMessage(), "NTLM token is null");
        }
    }

    @Test
    public void testValidateGrantForUnAuthenticatedState() throws Exception {

        mockStatic(WindowsAuthProviderImpl.class);
        mockStatic(WindowsCredentialsHandleImpl.class);
        mockStatic(WindowsAccountImpl.class);

        MockitoAnnotations.initMocks(this);

        whenNew(WindowsAuthProviderImpl.class).withAnyArguments().thenReturn(windowsAuthProvider);
        when(WindowsCredentialsHandleImpl.getCurrent(SECURITY_PACKAGE)).thenReturn(windowsCredentialsHandle);
        when(WindowsAccountImpl.getCurrentUsername()).thenReturn(CURRENT_USERNAME);

        whenNew(WindowsSecurityContextImpl.class).withAnyArguments().thenReturn(windowsSecurityContext);
        doNothing().when(windowsSecurityContext).initialize(null, null, CURRENT_USERNAME);

        Sspi.CtxtHandle ctxtHandle = new Sspi.CtxtHandle();
        when(windowsSecurityContext.getHandle()).thenReturn(ctxtHandle);
        byte[] continueTokenBytes = Base64.decode(TOKEN_STRING);
        Sspi.SecBufferDesc secBufferDesc = new Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, continueTokenBytes);
        whenNew(Sspi.SecBufferDesc.class).withArguments(Sspi.SECBUFFER_TOKEN, continueTokenBytes).thenReturn
                (secBufferDesc);
        doThrow(new RuntimeException()).when(windowsSecurityContext).initialize(ctxtHandle, secBufferDesc, "localhost");
        when(windowsSecurityContext.getToken()).thenReturn(TOKEN.getBytes());

        NTLMAuthenticationGrantHandler ntlmAuthenticationGrantHandler = new NTLMAuthenticationGrantHandler();
        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setWindowsToken(TOKEN);
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = new OAuthTokenReqMessageContext(
                oAuth2AccessTokenReqDTO);
        try {
            ntlmAuthenticationGrantHandler.validateGrant(oAuthTokenReqMessageContext);
            Assert.fail("Expectation is to have a IdentityOAuth2Exception here and it seems it is not throwing.");
        } catch (IdentityOAuth2Exception e) {
            Assert.assertEquals(e.getMessage(), "Error while validating the NTLM authentication grant");
        }
    }
}