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

package org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js;

import jdk.nashorn.api.scripting.AbstractJSObject;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

public class JsAuthenticatedUser extends AbstractJSObject {
    private AuthenticatedUser wrapped;

    public JsAuthenticatedUser(AuthenticatedUser wrapped) {
        this.wrapped = wrapped;
    }

    @Override
    public Object getMember(String name) {
        switch (name) {
        case "authenticatedSubjectIdentifier":
            return wrapped.getAuthenticatedSubjectIdentifier();
        default:
            return super.getMember(name);
        }
    }

    @Override
    public boolean hasMember(String name) {
        switch (name) {
        case "authenticatedSubjectIdentifier":
            return wrapped != null && wrapped.getAuthenticatedSubjectIdentifier() != null;
        default:
            return super.hasMember(name);
        }
    }
}
