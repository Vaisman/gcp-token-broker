// Copyright 2020 Google LLC
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.cloud.broker.apps.brokerserver.endpoints;

import java.util.Arrays;
import java.util.List;

import com.google.common.base.Preconditions;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import org.slf4j.MDC;

import com.google.cloud.broker.apps.brokerserver.logging.LoggingUtils;
import com.google.cloud.broker.apps.brokerserver.validation.Validation;
import com.google.cloud.broker.apps.brokerserver.validation.ProxyUserValidation;
import com.google.cloud.broker.apps.brokerserver.sessions.SessionAuthenticator;
import com.google.cloud.broker.authentication.backends.AbstractAuthenticationBackend;
import com.google.cloud.broker.apps.brokerserver.sessions.Session;
import com.google.cloud.broker.apps.brokerserver.accesstokens.AccessToken;
import com.google.cloud.broker.apps.brokerserver.accesstokens.AccessTokenCacheFetcher;

// Classes dynamically generated by protobuf-maven-plugin:
import com.google.cloud.broker.apps.brokerserver.protobuf.GetAccessTokenRequest;
import com.google.cloud.broker.apps.brokerserver.protobuf.GetAccessTokenResponse;


public class GetAccessToken {

    public static void run(GetAccessTokenRequest request, StreamObserver<GetAccessTokenResponse> responseObserver) {
        // First try to authenticate the session, if any.
        SessionAuthenticator sessionAuthenticator = new SessionAuthenticator();
        Session session = sessionAuthenticator.authenticateSession();

        // Fetch parameters from the request
        String owner = request.getOwner();
        List<String> scopes = request.getScopesList();
        String target = request.getTarget();

        if (session == null) {  // No session token was provided. The client is using direct authentication.
            // Assert that the parameters were provided
            Validation.validateParameterNotEmpty("owner", owner);
            Validation.validateParameterNotEmpty("scopes", scopes);
            Validation.validateParameterNotEmpty("target", target);

            // No session token was provided. The client is using direct authentication.
            // So let's authenticate the user.
            AbstractAuthenticationBackend authenticator = AbstractAuthenticationBackend.getInstance();
            String authenticatedUser = authenticator.authenticateUser();

            // If the authenticated user requests an access token for another user,
            // verify that it is allowed to do so.
            if (! authenticatedUser.equals(owner)) {
                ProxyUserValidation.validateImpersonator(authenticatedUser, owner);
            }
        }
        else {  // A session token was provided. The client is using delegated authentication.
            // Assert that no parameters were provided
            Validation.validateParameterIsEmpty("owner", owner);
            Validation.validateParameterIsEmpty("scopes", scopes);
            Validation.validateParameterIsEmpty("target", target);

            // Fetch the correct parameters from the session
            owner = session.getOwner();
            target = session.getTarget();
            scopes = Arrays.asList(session.getScopes().split(","));
        }

        AccessToken accessToken = (AccessToken) new AccessTokenCacheFetcher(owner, scopes).fetch();

        // Log success message
        MDC.put("owner", owner);
        MDC.put("scopes", String.join(",", scopes));
        MDC.put("target", target);
        if (session == null) {
            MDC.put("auth_mode", "direct");
        }
        else {
            MDC.put("auth_mode", "delegated");
            MDC.put("session_id", session.getId());
        }
        LoggingUtils.logSuccess(GetAccessToken.class.getSimpleName());

        // Return the response
        GetAccessTokenResponse response = GetAccessTokenResponse.newBuilder()
            .setAccessToken(accessToken.getValue())
            .setExpiresAt(accessToken.getExpiresAt())
            .build();
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

}
