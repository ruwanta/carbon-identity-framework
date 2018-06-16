/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authentication.framework.handler.sequence.impl.sequence;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.loader.UIBasedConfigurationLoader;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsFunctionRegistryImpl;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGraphBuilderFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.sequence.impl.AsyncSequenceExecutor;
import org.wso2.carbon.identity.application.authentication.framework.handler.sequence.impl.GraphBasedSequenceHandler;
import org.wso2.carbon.identity.application.authentication.framework.handler.sequence.impl.api.MockAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.handler.sequence.impl.api.SubjectCallback;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.dao.CacheBackedIdPMgtDAO;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.stream.XMLStreamException;

import static org.mockito.Mockito.*;

/**
 * Framework runner for Javascript based Sequence execution.
 */
public class JsSequenceHandlerRunner {

    private static final Log log = LogFactory.getLog(JsSequenceHandlerRunner.class);

    protected GraphBasedSequenceHandler graphBasedSequenceHandler = new GraphBasedSequenceHandler();
    protected UIBasedConfigurationLoader configurationLoader;
    protected JsGraphBuilderFactory graphBuilderFactory;
    private Class callerClass;

    private String applicationAuthenticationXmlFileName = "application-authentication.xml";

    public void init(Class caller, String applicationAuthenticationXmlFileName) throws InvocationTargetException {

        this.callerClass = caller;
        this.applicationAuthenticationXmlFileName = applicationAuthenticationXmlFileName;
        configurationLoader = new UIBasedConfigurationLoader();
        graphBuilderFactory = new JsGraphBuilderFactory();

        JsFunctionRegistryImpl jsFunctionRegistry = new JsFunctionRegistryImpl();
        FrameworkServiceDataHolder.getInstance().setJsFunctionRegistry(jsFunctionRegistry);

        graphBuilderFactory.init();
        FrameworkServiceDataHolder.getInstance().setJsGraphBuilderFactory(graphBuilderFactory);

        AsyncSequenceExecutor asyncSequenceExecutor = new AsyncSequenceExecutor();
        asyncSequenceExecutor.init();
        FrameworkServiceDataHolder.getInstance().setAsyncSequenceExecutor(asyncSequenceExecutor);
        reset();
    }

    private void reset() throws InvocationTargetException {

        URL root = this.getClass().getClassLoader().getResource(".");
        File file = new File(root.getPath());
        System.setProperty("carbon.home", file.toString());
        resetAuthenticators();

        FrameworkServiceDataHolder.getInstance().setRealmService(mock(RealmService.class));

        CacheBackedIdPMgtDAO cacheBackedIdPMgtDAO = mock(CacheBackedIdPMgtDAO.class);
        Field daoField = null;
        try {
            daoField = IdentityProviderManager.class.getDeclaredField("dao");
            daoField.setAccessible(true);
            daoField.set(IdentityProviderManager.getInstance(), cacheBackedIdPMgtDAO);

            RealmService mockRealmService = mock(RealmService.class);
            TenantManager tenantManager = mock(TenantManager.class);
            when(tenantManager.getTenantId(anyString())).thenReturn(1);
            when(mockRealmService.getTenantManager()).thenReturn(tenantManager);
            IdentityTenantUtil.setRealmService(mockRealmService);

            Field configFilePathField = FileBasedConfigurationBuilder.class.getDeclaredField("configFilePath");
            configFilePathField.setAccessible(true);
            URL url = callerClass.getResource(applicationAuthenticationXmlFileName);
            configFilePathField.set(null, url.getPath());
        } catch (NoSuchFieldException e) {
            throw new InvocationTargetException(e, "Could not inject mock objects to test runtime");
        } catch (UserStoreException e) {
            throw new InvocationTargetException(e, "Could not inject mock user store to test runtime");
        } catch (IllegalAccessException e) {
            throw new InvocationTargetException(e, "Failed to inject mock objects to test runtime");
        }
    }

    public void handle(HttpServletRequest req, HttpServletResponse resp, AuthenticationContext context) throws
            FrameworkException {

        graphBasedSequenceHandler.handle(req, resp, context);
    }

    public SequenceConfig getSequenceConfig(AuthenticationContext context, Map<String, String[]> parameterMap,
                                            ServiceProvider serviceProvider) throws FrameworkException {

        return configurationLoader.getSequenceConfig(context, parameterMap, serviceProvider);
    }

    public HttpServletRequest createHttpServletRequest() {

        HttpServletRequest req = mock(HttpServletRequest.class);
        Map<String, Object> attributes = new HashMap<>();
        doAnswer(m -> attributes.put(m.getArgumentAt(0, String.class), m.getArguments()[1])).when(req)
                .setAttribute(anyString(), any());

        doAnswer(m -> attributes.get(m.getArgumentAt(0, String.class))).when(req).getAttribute(anyString());

        return req;
    }

    public HttpServletResponse createHttpServletResponse() throws IOException {

        HttpServletResponse res = mock(HttpServletResponse.class);
        PrintWriter writer = new PrintWriter(System.out);
        doReturn(writer).when(res).getWriter();

        return res;
    }

    public ServiceProvider loadServiceProviderFromResource(String spFileName, Object loader) throws XMLStreamException {

        InputStream inputStream = loader.getClass().getResourceAsStream(spFileName);
        OMElement documentElement = new StAXOMBuilder(inputStream).getDocumentElement();
        return ServiceProvider.build(documentElement);
    }

    public AuthenticationContext createAuthenticationContext(ServiceProvider serviceProvider) {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setServiceProviderName(serviceProvider.getApplicationName());
        authenticationContext.setTenantDomain("test_domain");
        authenticationContext.setCurrentStep(1);
        authenticationContext.setContextIdentifier(UUID.randomUUID().toString());
        return authenticationContext;
    }

    protected void resetAuthenticators() {

        FrameworkServiceDataHolder.getInstance().getAuthenticators().clear();
        FrameworkServiceDataHolder.getInstance().getAuthenticators()
                .add(new MockAuthenticator("BasicMockAuthenticator", new MockSubjectCallback()));
        FrameworkServiceDataHolder.getInstance().getAuthenticators().add(new MockAuthenticator("HwkMockAuthenticator"));
        FrameworkServiceDataHolder.getInstance().getAuthenticators().add(new MockAuthenticator("FptMockAuthenticator"));
    }

    protected static class MockSubjectCallback implements SubjectCallback, Serializable {

        private static final long serialVersionUID = 597048141496121100L;

        @Override
        public AuthenticatedUser getAuthenticatedUser(AuthenticationContext context) {

            AuthenticatedUser result = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier("test_user");
            result.getUserAttributes().put(ClaimMapping
                                                   .build("http://wso2.org/claims/givenname",
                                                          "http://wso2.org/claims/givenname", "Test", false),
                                           "Test");
            result.getUserAttributes().put(ClaimMapping
                                                   .build("http://wso2.org/claims/lastname",
                                                          "http://wso2.org/claims/lastname", "Test", false),
                                           "User");
            return result;
        }
    }
}
