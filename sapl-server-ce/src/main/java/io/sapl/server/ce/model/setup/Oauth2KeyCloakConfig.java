/*
 * Copyright (C) 2017-2024 Dominic Heutelbeck (dominic@heutelbeck.com)
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.sapl.server.ce.model.setup;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Oauth2KeyCloakConfig {
    static final String CLIENT_ID_PATH         = "spring.security.oauth2.client.registration.keycloak.client-id";
    static final String CLIENT_SECRET_PATH     = "spring.security.oauth2.client.registration.keycloak.client-secret";
    static final String ISSUER_URI_PATH        = "spring.security.oauth2.client.provider.keycloak.issuer-uri";
    static final String JWK_SET_URI_PATH       = "spring.security.oauth2.client.provider.keycloak.jwk-set-uri";
    static final String AUTHORIZATION_URI_PATH = "spring.security.oauth2.client.provider.keycloak.authorization-uri";
    static final String TOKEN_URI_PATH         = "spring.security.oauth2.client.provider.keycloak.token-uri";
    static final String USER_INFO_URI_PATH     = "spring.security.oauth2.client.provider.keycloak.user-info-uri";

    private String clientId;
    private String clientSecret;
    private String issuerUri;
    private String jwkSetUri;
    private String authorizationUri;
    private String tokenUri;
    private String userInfoUri;

    private boolean saved = false;
}
