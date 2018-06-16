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

package org.wso2.carbon.identity.application.authentication.framework.handler.sequence.impl;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.wso2.carbon.identity.application.authentication.framework.AbstractFrameworkTest;
import org.wso2.carbon.identity.application.authentication.framework.handler.sequence.impl.sequence.JsSequenceHandlerRunner;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class GraphBasedSequenceHandlerAbstractTest extends AbstractFrameworkTest {

    protected static final String APPLICATION_AUTHENTICATION_FILE_NAME = "application-authentication-GraphStepHandlerTest.xml";
    protected JsSequenceHandlerRunner sequenceHandlerRunner;

    @BeforeClass
    protected void setupSuite() {

    }

    @BeforeMethod
    protected void setUp() throws InvocationTargetException {

        sequenceHandlerRunner = new JsSequenceHandlerRunner();
        sequenceHandlerRunner.init(this.getClass(), APPLICATION_AUTHENTICATION_FILE_NAME);
    }

    protected HttpServletRequest createMockHttpServletRequest() {

        return sequenceHandlerRunner.createHttpServletRequest();
    }

    protected HttpServletResponse createMockHttpServletResponse() throws IOException {

        return sequenceHandlerRunner.createHttpServletResponse();
    }
}
