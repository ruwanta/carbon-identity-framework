/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authentication.framework.demo.request;

import org.apache.commons.lang.StringUtils;
import org.mockito.ArgumentCaptor;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AbstractFrameworkTest;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationContextCache;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationContextCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationContextCacheKey;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.loader.UIBasedConfigurationLoader;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGraphBuilderFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.TransportDataExtractor;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.TransportDataExtractorRegistry;
import org.wso2.carbon.identity.application.authentication.framework.handler.sequence.impl.GraphBasedSequenceHandler;
import org.wso2.carbon.identity.application.authentication.framework.internal.impl.ExtensionHolder;
import org.wso2.carbon.identity.application.authentication.framework.internal.impl.TransportDataExtractorRegistryImpl;
import org.wso2.carbon.identity.application.authentication.framework.store.JavascriptCache;
import org.wso2.carbon.identity.application.authentication.framework.store.JavascriptCacheImpl;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.internal.ServiceReferenceHolder;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.dao.CacheBackedIdPMgtDAO;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.io.File;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.stream.XMLStreamException;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@Test
public class AdaptiveRequestCoordinatorTest extends AbstractFrameworkTest {

    protected static final String APPLICATION_AUTHENTICATION_FILE_NAME = "application-authentication.xml";
    private AdaptiveRequestCoordinator requestCoordinator;
    private GraphBasedSequenceHandler graphBasedSequenceHandler;
    protected JsGraphBuilderFactory graphBuilderFactory;
    protected JavascriptCache javascriptCache;

    @BeforeClass
    public void setUp() throws NoSuchFieldException, IllegalAccessException, XMLStreamException,
            IdentityApplicationManagementException {
        RealmService realmService = mock(RealmService.class);
        when(realmService.getTenantManager()).thenReturn(mock(TenantManager.class));

        ServiceReferenceHolder.getInstance().setRealmService(realmService);
        graphBuilderFactory = new JsGraphBuilderFactory();
        graphBuilderFactory.init();

        javascriptCache = new JavascriptCacheImpl();
        graphBuilderFactory.setJavascriptCache(javascriptCache);

        URL root = this.getClass().getClassLoader().getResource(".");
        File file = new File(root.getPath());
        System.setProperty("carbon.home", file.toString());

        Field configFilePathField = FileBasedConfigurationBuilder.class.getDeclaredField("configFilePath");
        configFilePathField.setAccessible(true);
        URL url = this.getClass().getResource(APPLICATION_AUTHENTICATION_FILE_NAME);
        configFilePathField.set(null, url.getPath());

        CacheBackedIdPMgtDAO cacheBackedIdPMgtDAO = mock(CacheBackedIdPMgtDAO.class);
        Field daoField = IdentityProviderManager.class.getDeclaredField("dao");
        daoField.setAccessible(true);
        daoField.set(IdentityProviderManager.getInstance(), cacheBackedIdPMgtDAO);

        UIBasedConfigurationLoader configurationLoader = new UIBasedConfigurationLoader();
        ExtensionHolder.getInstance()
                .addExtension(FrameworkConstants.Config.QNAME_SEQUENCE_LOADER, configurationLoader);

        ApplicationManagementService applicationManagementService = mock(ApplicationManagementService.class);
        when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(getTestServiceProvider("js-sp-user-agent.xml"));

        requestCoordinator = new AdaptiveRequestCoordinator();
        requestCoordinator.setApplicationManagementService(applicationManagementService);
        ExtensionHolder.getInstance()
                .addExtension(FrameworkConstants.Config.QNAME_EXT_REQ_COORDINATOR, requestCoordinator);
        //        requestCoordinator.setJsFunctionRegistrar();
        requestCoordinator.setJsGraphBuilderFactory(graphBuilderFactory);

        graphBasedSequenceHandler = new GraphBasedSequenceHandler();

        Map<AuthenticationContextCacheKey, AuthenticationContextCacheEntry> authenticationContextCache = new HashMap<>();
        Field authenticationContextCacheInstance = AuthenticationContextCache.class.getDeclaredField("instance");
        authenticationContextCacheInstance.setAccessible(true);
        AuthenticationContextCache mockAuthenticationContextCache = mock(AuthenticationContextCache.class);
        authenticationContextCacheInstance.set(null, mockAuthenticationContextCache);

        doAnswer(invocation -> {
            AuthenticationContextCacheKey key = (AuthenticationContextCacheKey) invocation.getArguments()[0];
            AuthenticationContextCacheEntry entry = (AuthenticationContextCacheEntry) invocation.getArguments()[1];
            authenticationContextCache.put(key, entry);
            return null;
        }).when(mockAuthenticationContextCache)
                .addToCache(any(AuthenticationContextCacheKey.class), any(AuthenticationContextCacheEntry.class));

        doAnswer(invocation -> {
            AuthenticationContextCacheKey key = (AuthenticationContextCacheKey) invocation.getArguments()[0];
            AuthenticationContextCacheEntry entry = authenticationContextCache.get(key);
            return null;
        }).when(mockAuthenticationContextCache).getValueFromCache(any(AuthenticationContextCacheKey.class));

    }

    @Test
    public void testInitializeFlow_Default() throws FrameworkException {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter(eq(FrameworkConstants.RequestParams.ISSUER))).thenReturn("test");
        when(req.getParameter(eq(FrameworkConstants.RequestParams.TYPE))).thenReturn("openid");

        HttpServletResponse resp = mock(HttpServletResponse.class);

        requestCoordinator.initializeFlow(req, resp);
    }

    @Test
    public void testHandle_Javascript() throws Exception {
        ExtensionHolder.getInstance()
                .addExtension(FrameworkConstants.Config.QNAME_EXT_STEP_BASED_SEQ_HANDLER, graphBasedSequenceHandler);

        ApplicationManagementService applicationManagementService = mock(ApplicationManagementService.class);
        when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(getTestServiceProvider("js-sp-user-agent-javascript.xml"));
        requestCoordinator.setApplicationManagementService(applicationManagementService);

        Map<String, String> parameters = new HashMap<>();
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter(eq(FrameworkConstants.RequestParams.ISSUER))).thenReturn("test");
        when(req.getParameter(eq(FrameworkConstants.RequestParams.TYPE))).thenReturn("openid");
        when(req.getParameter(anyString())).then(i -> parameters.get(i.getArguments()[0]));
        doAnswer(i -> {
            parameters.put((String) i.getArguments()[0], i.getArguments()[1].toString());
            return null;
        }).when(req).setAttribute(anyString(), anyObject());

        ArgumentCaptor<String> redirectCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        HttpServletResponse resp = mock(HttpServletResponse.class);

        //        ExtensionHolder.getInstance().addExtension(FrameworkConstants.Config.QNAME_EXT_AUTH_REQ_HANDLER, mock(
        //                AuthenticationRequestHandler.class));

        requestCoordinator.handle(req, resp);
        requestCoordinator.handle(req, resp);
        requestCoordinator.handle(req, resp);
        verify(resp, times(3)).sendRedirect(redirectCaptor.capture());
        redirectCaptor.getAllValues().stream().forEach(s -> System.out.println(s));
        cookieCaptor.getAllValues().stream().forEach(c -> System.out.println(c));
        parameters.entrySet().stream().forEach(p -> System.out.println(p.getKey() +" - "+p.getValue() ));
    }

    @Test
    public void testInitializeFlow_UserAgent() throws FrameworkException {
        MockUserAgentExtractor userAgentExtractor = new MockUserAgentExtractor();

        TransportDataExtractorRegistry transportDataExtractorRegistry = new TransportDataExtractorRegistryImpl();
        transportDataExtractorRegistry.register("UserAgent", userAgentExtractor);

        requestCoordinator.setTransportDataExtractorRegistry(transportDataExtractorRegistry);

        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter(eq(FrameworkConstants.RequestParams.ISSUER))).thenReturn("test");
        when(req.getParameter(eq(FrameworkConstants.RequestParams.TYPE))).thenReturn("openid");
        when(req.getHeader(MockUserAgentExtractor.USER_AGENT_HEADER)).thenReturn(
                "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.4; fr; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5,gzip(gfe),gzip(gfe)");

        HttpServletResponse resp = mock(HttpServletResponse.class);

        AuthenticationContext authenticationContext = requestCoordinator.initializeFlow(req, resp);
        assertNotNull(authenticationContext);
        assertNotNull(authenticationContext.getProperty("CLIENT_BROWSER"));
        assertEquals(authenticationContext.getProperty("CLIENT_BROWSER"), "Mozilla");

    }

    private class MockUserAgentExtractor implements TransportDataExtractor {

        public static final String USER_AGENT_HEADER = "User-Agent";

        @Override
        public void process(HttpServletRequest request, AuthenticationContext authenticationContext) {
            String uaHeader = request.getHeader(USER_AGENT_HEADER);
            if (StringUtils.isNotEmpty(uaHeader)) {

                String os = detectOs(uaHeader);
                String browser = detectBrowser(uaHeader);
                String device = detectDevice(uaHeader);

                authenticationContext.setProperty("CLIENT_OS", os);
                authenticationContext.setProperty("CLIENT_BROWSER", browser);
                authenticationContext.setProperty("CLIENT_DEVICE", device);
            }
        }

        private String detectDevice(String uaHeader) {
            return null;
        }

        private String detectBrowser(String uaHeader) {
            if (uaHeader.contains("Mozilla")) {
                return "Mozilla";
            }
            return null;
        }

        private String detectOs(String uaHeader) {
            if (uaHeader.contains("Mozilla")) {
                return "Mozilla";
            }
            return null;
        }

    }
}