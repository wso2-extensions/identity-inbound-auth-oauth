package org.wso2.carbon.identity.oauth;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.engine.AxisConfiguration;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.internal.util.reflection.FieldSetter;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementServiceImpl;
import org.wso2.carbon.identity.application.mgt.inbound.dto.InboundProtocolsDTO;
import org.wso2.carbon.identity.core.internal.IdentityCoreServiceComponent;
import org.wso2.carbon.identity.cors.mgt.core.CORSManagementService;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({ OAuth2ServiceComponentHolder.class, OAuthComponentServiceHolder.class, PrivilegedCarbonContext.class})
public class OAuthProtocolManagementServiceTest extends PowerMockTestCase {
    
    @Mock
    private OAuthAdminServiceImpl oAuthAdminService;
    @Mock
    private ServiceProvider application;
    @Mock
    private ConfigurationContext configurationContext;
    @Mock
    private AxisConfiguration axisConfiguration;
    @InjectMocks
    private OauthInboundAuthConfigHandler authConfigHandler;
    @Mock
    private OAuth2ServiceComponentHolder mockOAuth2ComponentServiceHolder;
    @Mock
    private ApplicationManagementServiceImpl applicationManagementService;
    @Mock
    private CORSManagementService corsManagementService;
    @Mock
    private OAuthComponentServiceHolder mockOAuthComponentServiceHolder;
    
    private static final String CLIENT_ID = "dummyClientId";
    private static final String APPLICATION_NAME = "dummyApplication";
    private static final String APPLICATION_RESOURCE_ID = "dummyResourceId";
    
    @BeforeMethod
    public void setUp() throws Exception {
        
        MockitoAnnotations.initMocks(this);
        System.setProperty("carbon.home",
                System.getProperty("user.dir") + File.separator + "src" + File.separator + "test"
                        + File.separator + "resources");
        
        initConfigsAndRealm();
    }
    
    @Test
    public void testCreateInboundOAuthProtocol() throws Exception {

        mockOAuth2ServiceComponentHolder();
        when(OAuth2ServiceComponentHolder.getInstance().getOAuthAdminService()).thenReturn(oAuthAdminService);
        
        InboundProtocolsDTO inboundProtocolsDTO = new InboundProtocolsDTO();
        inboundProtocolsDTO.addProtocolConfiguration(new OAuthConsumerAppDTO());
        
        OAuthConsumerAppDTO updatedOAuthConsumerAppDTO = new OAuthConsumerAppDTO();
        updatedOAuthConsumerAppDTO.setAuditLogData(getDummyMap());
        when(oAuthAdminService.registerAndRetrieveOAuthApplicationData(any(), eq(false)))
                .thenReturn(updatedOAuthConsumerAppDTO);

        // We don't need the service provider object for OAuth protocol creation.
        InboundAuthenticationRequestConfig result = authConfigHandler.handleConfigCreation(null, inboundProtocolsDTO);

        // Verify that the OAuthAdminService is called with the correct parameters.
        verify(oAuthAdminService, times(0)).registerAndRetrieveOAuthApplicationData(any(), eq(true));
        verify(oAuthAdminService, times(1)).registerAndRetrieveOAuthApplicationData(any(), eq(false));

        // Asserting the audit log data is added to the result.
        Assert.assertFalse(result.getData().isEmpty());
        Assert.assertEquals(result.getInboundAuthType(), FrameworkConstants.StandardInboundProtocols.OAUTH2);
    }
    
    @Test
    public void testUpdateOAuthProtocol() throws Exception {
        
        mockPrivilegeCarbonContext();
        mockApplicationManagementService();
        mockCorsManagementService();
        mockOAuth2ServiceComponentHolder();
        mockServiceProvider();
        
        OAuthConsumerAppDTO oAuthConsumerAppDTO = new OAuthConsumerAppDTO();
        oAuthConsumerAppDTO.setAuditLogData(getDummyMap());
        oAuthConsumerAppDTO.setOauthConsumerKey(CLIENT_ID);
        
        // Mock behavior when currentClientId is not null, indicating an existing application.
        when(oAuthAdminService.getOAuthApplicationData(any())).thenReturn(oAuthConsumerAppDTO);
        doNothing().when(oAuthAdminService).updateConsumerApplication(eq(oAuthConsumerAppDTO), eq(false));
        
        authConfigHandler.handleConfigUpdate(application, oAuthConsumerAppDTO);
        
        verify(oAuthAdminService, times(1)).getOAuthApplicationData(eq(CLIENT_ID));
        verify(oAuthAdminService, times(1)).updateConsumerApplication(eq(oAuthConsumerAppDTO),
                eq(false));
    }
    
    @Test
    public void testUpdateOAuthProtocol_CreateNewApplication() throws Exception {

        mockOAuth2ServiceComponentHolder();
        mockCorsManagementService();

        OAuthConsumerAppDTO oAuthConsumerAppDTO = new OAuthConsumerAppDTO();
        oAuthConsumerAppDTO.setAuditLogData(getDummyMap());

        // Mock behavior when currentClientId is null, indicating a new application
        when(oAuthAdminService.getOAuthApplicationData(any())).thenReturn(null);
        when(oAuthAdminService.registerAndRetrieveOAuthApplicationData(eq(oAuthConsumerAppDTO), eq(false)))
                .thenReturn(oAuthConsumerAppDTO);

        InboundAuthenticationRequestConfig result = authConfigHandler.handleConfigUpdate(application,
                oAuthConsumerAppDTO);

        // Verify that the createOAuthProtocol function is executed
        verify(oAuthAdminService, times(0)).registerAndRetrieveOAuthApplicationData(
                eq(oAuthConsumerAppDTO), eq(true));
        // Verify that the createOAuthProtocol function is not executed without audit logs
        verify(oAuthAdminService, times(1)).registerAndRetrieveOAuthApplicationData(
                eq(oAuthConsumerAppDTO), eq(false));

        Assert.assertFalse(result.getData().isEmpty());
    }
    
    @Test
    public void testUpdateOAuthProtocol_RollbackOnException() throws Exception {

        mockPrivilegeCarbonContext();
        mockApplicationManagementService();
        mockCorsManagementService();
        mockOAuth2ServiceComponentHolder();
        mockServiceProvider();

        OAuthConsumerAppDTO oAuthConsumerAppDTO = new OAuthConsumerAppDTO();
        oAuthConsumerAppDTO.setAuditLogData(getDummyMap());
        oAuthConsumerAppDTO.setOauthConsumerKey(CLIENT_ID);

        // Mock behavior when currentClientId is not null, indicating an existing application.
        when(oAuthAdminService.getOAuthApplicationData(any())).thenReturn(oAuthConsumerAppDTO);

        // Mock an exception to trigger the rollback scenario when updateApplicationByResourceId is called
        doThrow(new IdentityOAuthAdminException("Simulated Exception")).when(oAuthAdminService)
                .updateConsumerApplication(eq(oAuthConsumerAppDTO), eq(false));
        when(applicationManagementService.getApplicationByResourceId(ArgumentMatchers.eq(APPLICATION_RESOURCE_ID),
                any())).thenReturn(application);

        try {
            authConfigHandler.handleConfigUpdate(application, oAuthConsumerAppDTO);
        } catch (IdentityApplicationManagementException e) {
            verify(oAuthAdminService, times(1)).updateConsumerApplication(eq(oAuthConsumerAppDTO),
                    eq(false));
            // Verify that setCorsOrigins is called twice, once before update and once during rollback.
            verify(corsManagementService, times(2)).setCORSOrigins(eq(APPLICATION_RESOURCE_ID),
                    any(), any());
        }
    }

    @Test
    public void testDeleteProtocol() throws Exception {

        mockPrivilegeCarbonContext();
        mockOAuth2ServiceComponentHolder();
        mockServiceProvider();

        authConfigHandler.handleConfigDeletion(CLIENT_ID);

        verify(oAuthAdminService, times(1)).removeOAuthApplicationData(eq(CLIENT_ID), eq(false));
    }
    
    private void mockOAuth2ServiceComponentHolder() {
        
        mockStatic(OAuth2ServiceComponentHolder.class);
        Mockito.when(OAuth2ServiceComponentHolder.getInstance()).thenReturn(mockOAuth2ComponentServiceHolder);
        when(mockOAuth2ComponentServiceHolder.getOAuthAdminService()).thenReturn(oAuthAdminService);
    }
    
    private void mockApplicationManagementService() {
        
        mockStatic(OAuthComponentServiceHolder.class);
        Mockito.when(OAuthComponentServiceHolder.getInstance()).thenReturn(mockOAuthComponentServiceHolder);
        Mockito.when(mockOAuthComponentServiceHolder.getApplicationManagementService()).thenReturn(
                applicationManagementService);
    }
    
    private void mockCorsManagementService() {
        
        mockStatic(OAuthComponentServiceHolder.class);
        Mockito.when(OAuthComponentServiceHolder.getInstance()).thenReturn(mockOAuthComponentServiceHolder);
        Mockito.when(mockOAuthComponentServiceHolder.getCorsManagementService()).thenReturn(corsManagementService);
    }
    
    private void mockPrivilegeCarbonContext() {
        
        mockStatic(PrivilegedCarbonContext.class);
        PrivilegedCarbonContext privilegedCarbonContext = mock(PrivilegedCarbonContext.class);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(privilegedCarbonContext);
    }
    
    private Map<String, Object> getDummyMap() {
        
        Map<String, Object> dummyMap = new HashMap<>();
        dummyMap.put("dummyKey", "dummyValue");
        return dummyMap;
    }
    
    private void mockServiceProvider() {
        
        this.application = new ServiceProvider();
        application.setApplicationName(APPLICATION_NAME);
        application.setApplicationResourceId(APPLICATION_RESOURCE_ID);
        InboundAuthenticationConfig inboundAuthenticationConfig = new InboundAuthenticationConfig();
        InboundAuthenticationRequestConfig inboundAuthConfig = new InboundAuthenticationRequestConfig();
        inboundAuthConfig.setInboundAuthKey(CLIENT_ID);
        inboundAuthConfig.setInboundAuthType(FrameworkConstants.StandardInboundProtocols.OAUTH2);
        inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(new InboundAuthenticationRequestConfig[]{
                inboundAuthConfig
        });
        application.setInboundAuthenticationConfig(inboundAuthenticationConfig);
    }
    
    private void initConfigsAndRealm() throws Exception {
        
        IdentityCoreServiceComponent identityCoreServiceComponent = new IdentityCoreServiceComponent();
        ConfigurationContextService configurationContextService = new ConfigurationContextService
                (configurationContext, null);
        FieldSetter.setField(identityCoreServiceComponent, identityCoreServiceComponent.getClass().
                getDeclaredField("configurationContextService"), configurationContextService);
        when(configurationContext.getAxisConfiguration()).thenReturn(axisConfiguration);
    }
}
