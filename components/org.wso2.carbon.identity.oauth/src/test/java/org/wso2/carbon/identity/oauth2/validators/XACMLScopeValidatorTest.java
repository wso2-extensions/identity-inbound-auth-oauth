package org.wso2.carbon.identity.oauth2.validators;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.balana.utils.exception.PolicyBuilderException;
import org.wso2.balana.utils.policy.PolicyBuilder;
import org.wso2.balana.utils.policy.dto.RequestElementDTO;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.EntitlementService;
import org.wso2.carbon.identity.entitlement.common.dto.RequestDTO;
import org.wso2.carbon.identity.entitlement.common.util.PolicyCreatorUtil;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;

/**
 * XACMLScopeValidatorTest defines unit tests for XACMLScopeValidator class.
 */
@PrepareForTest({LogFactory.class, FrameworkUtils.class, PolicyCreatorUtil.class, PolicyBuilder.class,
        OAuth2Util.class})
@PowerMockIgnore("javax.xml.*")
@WithCarbonHome
public class XACMLScopeValidatorTest extends IdentityBaseTest {

    private static final String ADMIN_USER = "admin_user";
    private static final String APP_NAME = "SP_APP";
    private static final String DECISION = "decision";
    private static final String RULE_EFFECT_PERMIT = "Permit";
    private static final String RULE_EFFECT_NOT_APPLICABLE = "NotApplicable";
    private static final String POLICY = "policy";
    private static final String ERROR = "error";
    private static String xacmlResponse = "<ns:root xmlns:ns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\">"
            + "<ns:Result>"
            + "<ns:Decision>"
            + DECISION
            + "</ns:Decision>"
            + "</ns:Result>"
            + "</ns:root>";
    private XACMLScopeValidator xacmlScopeValidator;
    private AccessTokenDO accessTokenDO;
    private OAuthAppDO authApp;
    private Log log = mock(Log.class);
    private String[] scopeArray;
    private String resource;


    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @BeforeClass
    public void init() {
        mockStatic(LogFactory.class);
        when(LogFactory.getLog(XACMLScopeValidator.class)).thenReturn(log);
        xacmlScopeValidator = spy(new XACMLScopeValidator());
        accessTokenDO = mock(AccessTokenDO.class);
        resource = mock(String.class);
        authApp = mock(OAuthAppDO.class);
        scopeArray = new String[]{"scope1", "scope2", "scope3"};
        when(log.isDebugEnabled()).thenReturn(true);
    }

    @Test
    public void testCreateRequestDTO() throws Exception {

        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(accessTokenDO.getAuthzUser()).thenReturn(authenticatedUser);
        when(accessTokenDO.getScope()).thenReturn(scopeArray);
        when(authenticatedUser.getUserName()).thenReturn(ADMIN_USER);
        when(authApp.getApplicationName()).thenReturn(APP_NAME);
        RequestDTO requestDTO = WhiteboxImpl.invokeMethod(xacmlScopeValidator,
                "createRequestDTO", accessTokenDO, authApp, resource);
        assertTrue(requestDTO.getRowDTOs().size() == 9);
    }

    @Test
    public void testEvaluateXACMLResponse() throws Exception {

        String response = WhiteboxImpl.invokeMethod(xacmlScopeValidator, "evaluateXACMLResponse",
                xacmlResponse);
        assertEquals(response, DECISION);
    }

    @Test
    public void testValidatedScope() throws Exception {
        mockStatic(FrameworkUtils.class);
        doNothing().when(FrameworkUtils.class);
        FrameworkUtils.endTenantFlow();

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(ADMIN_USER);
        when(accessTokenDO.getAuthzUser()).thenReturn(authenticatedUser);
        when(accessTokenDO.getConsumerKey()).thenReturn(mock(String.class));

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(authApp);

        RequestElementDTO requestElementDTO = mock(RequestElementDTO.class);
        mockStatic(PolicyCreatorUtil.class);
        when(PolicyCreatorUtil.createRequestElementDTO(any(RequestDTO.class))).thenReturn(requestElementDTO);
        PolicyBuilder policyBuilder = mock(PolicyBuilder.class);
        mockStatic(PolicyBuilder.class);
        when(PolicyBuilder.getInstance()).thenReturn(policyBuilder);
        when(policyBuilder.buildRequest(any(RequestElementDTO.class))).thenReturn(POLICY);
        EntitlementService entitlementService = mock(EntitlementService.class);
        OAuth2ServiceComponentHolder.setEntitlementService(entitlementService);

        when(entitlementService.getDecision(anyString())).thenReturn(xacmlResponse);
        assertFalse(xacmlScopeValidator.validateScope(accessTokenDO, resource));

        xacmlResponse = xacmlResponse.replace(DECISION, RULE_EFFECT_NOT_APPLICABLE);
        when(entitlementService.getDecision(anyString())).thenReturn(xacmlResponse);
        assertTrue(xacmlScopeValidator.validateScope(accessTokenDO, resource));

        xacmlResponse = xacmlResponse.replace(RULE_EFFECT_NOT_APPLICABLE, RULE_EFFECT_PERMIT);
        when(entitlementService.getDecision(anyString())).thenReturn(xacmlResponse);
        assertTrue(xacmlScopeValidator.validateScope(accessTokenDO, resource));

        when(entitlementService.getDecision(anyString())).thenThrow(new EntitlementException(ERROR));
        assertFalse(xacmlScopeValidator.validateScope(accessTokenDO, resource));

        when(policyBuilder.buildRequest(any(RequestElementDTO.class))).thenThrow(new PolicyBuilderException(ERROR));
        assertFalse(xacmlScopeValidator.validateScope(accessTokenDO, resource));
    }
}