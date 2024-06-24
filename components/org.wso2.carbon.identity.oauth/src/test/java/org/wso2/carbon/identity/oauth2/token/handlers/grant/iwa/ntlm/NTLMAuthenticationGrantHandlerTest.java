package org.wso2.carbon.identity.oauth2.token.handlers.grant.iwa.ntlm;

import com.sun.jna.platform.win32.Sspi;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.iwa.ntlm.util.SimpleHttpRequest;
import waffle.util.Base64;
import waffle.windows.auth.impl.WindowsAccountImpl;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;
import waffle.windows.auth.impl.WindowsCredentialsHandleImpl;
import waffle.windows.auth.impl.WindowsSecurityContextImpl;

import java.security.Principal;

import javax.security.auth.Subject;
import javax.servlet.http.HttpSession;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.notNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/* To run this test class you need to ensure that a JDK that targets x64 architecture is installed.
If the installed JDK targets the aarch64 (ARM) architecture, the test will fail with an UnsatisfiedLinkError. */
public class NTLMAuthenticationGrantHandlerTest {

    private static final String SECURITY_PACKAGE = "Negotiate";
    private static final String TOKEN = "tretertertert43t3t43t34t3t3t3";
    private static final String CURRENT_USERNAME = "test\\testdomain/testuser.carbon.super";
    private static final String TOKEN_STRING = " NTLM, Basic realm=\"BasicSecurityFilterProvider\"";
    private static final String PRINCIPAL_NAME = "testPrincipal";

    private static final String SECURITY_HEADER = "javax.security.auth.subject";

    @Mock
    private OAuthServerConfiguration serverConfiguration;
    @Mock
    private WindowsCredentialsHandleImpl mockWindowsCredentialsHandle;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;

    @DataProvider
    public Object[][] getValidateGrantTypeHandlerData() {

        return new Object[][]{{null}, {TOKEN}};
    }

    @BeforeMethod
    public void setUp() throws Exception {

        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        MockitoAnnotations.initMocks(this);

        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(serverConfiguration);
    }

    @AfterMethod
    public void tearDown() {

        oAuthServerConfiguration.close();
    }

    @Test
    public void testIssueRefreshToken() throws Exception {

        NTLMAuthenticationGrantHandler ntlmAuthenticationGrantHandler = new NTLMAuthenticationGrantHandler();
        boolean ret = ntlmAuthenticationGrantHandler.issueRefreshToken();
        Assert.assertEquals(ret, false);
    }

    @Test(dataProvider = "getValidateGrantTypeHandlerData")
    public void testValidateGrant(String token) throws Exception {

        try (MockedStatic<WindowsCredentialsHandleImpl> windowsCredentialsHandle = mockStatic(
                WindowsCredentialsHandleImpl.class);
             MockedStatic<WindowsAccountImpl> windowsAccount = mockStatic(WindowsAccountImpl.class)) {

            try (MockedConstruction<WindowsAuthProviderImpl> authProviderMockedConstruction = mockConstruction(
                    WindowsAuthProviderImpl.class, (mock, context) -> {
                        when(mock.acceptSecurityToken(anyString(), any(), anyString())).thenAnswer(invocation -> null);
                    })) {

                windowsCredentialsHandle.when(() -> WindowsCredentialsHandleImpl.getCurrent(SECURITY_PACKAGE))
                        .thenReturn(this.mockWindowsCredentialsHandle);
                windowsAccount.when(WindowsAccountImpl::getCurrentUsername).thenReturn(CURRENT_USERNAME);

                Sspi.CtxtHandle ctxtHandle = new Sspi.CtxtHandle();
                byte[] continueTokenBytes = Base64.decode(TOKEN_STRING);
                try (MockedConstruction<WindowsSecurityContextImpl> mockedConstruction = mockConstruction(
                        WindowsSecurityContextImpl.class, (mock, context) -> {
                            doNothing().when(mock).initialize(null, null, CURRENT_USERNAME);
                            when(mock.getHandle()).thenReturn(ctxtHandle);
                            doNothing().when(mock).initialize(any(), any(), anyString());
                            if (token != null) {
                                when(mock.getToken()).thenReturn(token.getBytes());
                            }
                        })) {
                    try (MockedConstruction<Sspi.SecBufferDesc> secBufferDescMockedConstruction = mockConstruction(
                            Sspi.SecBufferDesc.class, (mock, context) -> {
                                when(mock.getBytes()).thenReturn(new Sspi.SecBuffer.ByReference(Sspi.SECBUFFER_TOKEN,
                                        Base64.decode(TOKEN_STRING)).getBytes());
                            })) {

                        NTLMAuthenticationGrantHandler ntlmAuthenticationGrantHandler =
                                new NTLMAuthenticationGrantHandler();
                        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
                        oAuth2AccessTokenReqDTO.setWindowsToken(token);
                        OAuthTokenReqMessageContext oAuthTokenReqMessageContext =
                                new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);

                        Subject subject = new Subject();
                        subject.getPrincipals().add(new Principal() {
                            @Override
                            public String getName() {

                                return PRINCIPAL_NAME;
                            }
                        });
                        try (MockedConstruction<SimpleHttpRequest> mockedConstruction1 = mockConstruction(
                                SimpleHttpRequest.class, (mock, context) -> {
                                    HttpSession httpSession = mock(HttpSession.class);
                                    when(mock.getSession()).thenReturn(httpSession);
                                    when(httpSession.getAttribute(SECURITY_HEADER)).thenReturn(subject);
                                })) {
                            try {
                                ntlmAuthenticationGrantHandler.validateGrant(oAuthTokenReqMessageContext);
                                AuthenticatedUser authorizedUser = oAuthTokenReqMessageContext.getAuthorizedUser();
                                Assert.assertNotNull(authorizedUser);
                                Assert.assertNotNull(authorizedUser.getUserName(), CURRENT_USERNAME);
                            } catch (IdentityOAuth2Exception e) {
                                Assert.assertEquals(e.getMessage(), "NTLM token is null");
                            }
                        }
                    }
                }
            }
        }
    }

    @Test
    public void testValidateGrantForUnAuthenticatedState() throws Exception {

        try (MockedStatic<WindowsCredentialsHandleImpl> windowsCredentialsHandle = mockStatic(
                WindowsCredentialsHandleImpl.class);
             MockedStatic<WindowsAccountImpl> windowsAccount = mockStatic(WindowsAccountImpl.class)) {

            try (MockedConstruction<WindowsAuthProviderImpl> authProviderMockedConstruction = mockConstruction(
                    WindowsAuthProviderImpl.class, (mock, context) -> {
                        when(mock.acceptSecurityToken(anyString(), any(), anyString())).thenAnswer(invocation -> null);
                    })) {

                windowsCredentialsHandle.when(() -> WindowsCredentialsHandleImpl.getCurrent(SECURITY_PACKAGE))
                        .thenReturn(this.mockWindowsCredentialsHandle);
                windowsAccount.when(WindowsAccountImpl::getCurrentUsername).thenReturn(CURRENT_USERNAME);

                Sspi.CtxtHandle ctxtHandle = new Sspi.CtxtHandle();
                byte[] continueTokenBytes = Base64.decode(TOKEN_STRING);
                try (MockedConstruction<WindowsSecurityContextImpl> mockedConstruction = mockConstruction(
                        WindowsSecurityContextImpl.class, (mock, context) -> {
                            doNothing().when(mock).initialize(null, null, CURRENT_USERNAME);
                            when(mock.getHandle()).thenReturn(ctxtHandle);
                            doThrow(new RuntimeException()).when(mock)
                                    .initialize(notNull(Sspi.CtxtHandle.class), notNull(Sspi.SecBufferDesc.class),
                                            anyString());
                            when(mock.getToken()).thenReturn(TOKEN.getBytes());
                        })) {
                    try (MockedConstruction<Sspi.SecBufferDesc> secBufferDescMockedConstruction = mockConstruction(
                            Sspi.SecBufferDesc.class, (mock, context) -> {
                                when(mock.getBytes()).thenReturn(new Sspi.SecBuffer.ByReference(Sspi.SECBUFFER_TOKEN,
                                        Base64.decode(TOKEN_STRING)).getBytes());
                            })) {

                        NTLMAuthenticationGrantHandler ntlmAuthenticationGrantHandler =
                                new NTLMAuthenticationGrantHandler();
                        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
                        oAuth2AccessTokenReqDTO.setWindowsToken(TOKEN);
                        OAuthTokenReqMessageContext oAuthTokenReqMessageContext =
                                new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);

                        try {
                            ntlmAuthenticationGrantHandler.validateGrant(oAuthTokenReqMessageContext);
                            Assert.fail(
                                    "Expectation is to have a IdentityOAuth2Exception here and it seems it is " +
                                            "not throwing.");
                        } catch (IdentityOAuth2Exception e) {
                            Assert.assertEquals(e.getMessage(), "Error while validating the NTLM authentication " +
                                    "grant");
                        }
                    }
                }
            }
        }
    }
}
