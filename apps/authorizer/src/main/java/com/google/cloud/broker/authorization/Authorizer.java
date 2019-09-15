/*
 * Copyright 2019 Google LLC
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

package com.google.cloud.broker.authorization;

import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.apache.v2.ApacheHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.Key;
import com.google.cloud.broker.encryption.backends.AbstractEncryptionBackend;
import com.google.cloud.broker.oauth.DatabaseRefreshTokenStore;
import com.google.cloud.broker.oauth.RefreshToken;
import com.google.cloud.broker.oauth.RefreshTokenStore;
import com.google.cloud.broker.settings.AppSettings;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.Resources;
import com.google.template.soy.SoyFileSet;
import com.google.template.soy.jbcsrc.api.SoySauce;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.security.Constraint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.URI;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;

public class Authorizer implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(Authorizer.class);
    private Server server;
    private static SoySauce soySauce;
    private CallbackServlet callbackServlet;
    private GoogleAuthorizationCodeFlow flow;

    static {
        SoyFileSet sfs = SoyFileSet.builder()
            .add(Resources.getResource("callback.soy"))
            .build();
        soySauce = sfs.compileTemplates();
    }

    public static final HttpTransport HTTP_TRANSPORT = new ApacheHttpTransport();
    public static final JacksonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
    public static final Credential.AccessMethod ACCESS_METHOD = BearerToken.queryParameterAccessMethod();
    private static SecureRandom rng = new SecureRandom();

    public static final String STATE_PARAM = "state";
    public static final String CODE_PARAM = "code";
    public static final String USER_INFO_URI = "https://www.googleapis.com/oauth2/v2/userinfo";
    public static final String AUTH_SERVER_URL = "https://accounts.google.com/o/oauth2/auth";
    public static final String TOKEN_URL = "https://oauth2.googleapis.com/token";
    public static final Set<String> SCOPES = ImmutableSet.of(
        "https://www.googleapis.com/auth/devstorage.read_write",
        "email",
        "profile");

    public static void main(String[] args) throws Exception {
        Authorizer authorizer = new Authorizer();
        authorizer.start();
        authorizer.join();
    }

    public Authorizer() throws LoginException {
        Settings settings = new Settings();
        String redirectUri = settings.callbackUri.toString();
        int opts = ServletContextHandler.GZIP | ServletContextHandler.SECURITY;
        ServletContextHandler ctx = new ServletContextHandler(opts);
        ctx.setContextPath("/");
        if (settings.enableSpnego) {
            // Require authentication
            Constraint constraint = new Constraint();
            constraint.setAuthenticate(true);
            constraint.setName("authn");
            constraint.setRoles(new String[]{"user"});

            // Require authentication on all paths
            ConstraintMapping cMap = new ConstraintMapping();
            cMap.setPathSpec("/*");
            cMap.setConstraint(constraint);

            // Require authentication on all paths using SPNEGO
            ConstraintSecurityHandler csh = new ConstraintSecurityHandler();
            csh.addConstraintMapping(cMap);

            LoginService loginService = new Spnego.SpnegoLoginService(settings.principal, settings.keytabPath, "user");
            Spnego.SpnegoLoginAuthenticator authenticator = new Spnego.SpnegoLoginAuthenticator();

            csh.setLoginService(loginService);
            csh.setAuthenticator(authenticator);

            csh.setIdentityService(new DefaultIdentityService());

            // Attach to ServletContextHandler
            ctx.setSecurityHandler(csh);
        }

        ctx.setSessionHandler(new SessionHandler());

        server = new Server(settings.port);
        server.setHandler(ctx);

        flow = new GoogleAuthorizationCodeFlow
            .Builder(HTTP_TRANSPORT,
                    JSON_FACTORY,
                    settings.clientId,
                    settings.clientSecret,
                    SCOPES)
            .setAuthorizationServerEncodedUrl(AUTH_SERVER_URL)
            .setTokenServerUrl(new GenericUrl(TOKEN_URL))
            .setMethod(ACCESS_METHOD)
            .setAccessType("offline") // refresh token is needed
            .build();

        ctx.addServlet(new ServletHolder(new LoginServlet(flow, settings.callbackUri.getPath())), "/");

        CallbackOptions callbackOptions = new CallbackOptions();
        callbackOptions.aead = AbstractEncryptionBackend.getInstance();
        callbackOptions.db = new DatabaseRefreshTokenStore();
        callbackOptions.flow = flow;
        callbackOptions.redirectUri = redirectUri;
        callbackServlet = new CallbackServlet(callbackOptions);

        ctx.addServlet(new ServletHolder(callbackServlet),
            settings.callbackUri.getPath());

        server.setStopAtShutdown(true);
    }

    @VisibleForTesting
    public CallbackServlet getCallbackServlet(){
        return callbackServlet;
    }

    public static class UserInfo extends GenericJson {
        @Key
        private String email;
        public String getEmail() {
            return email;
        }

        @Key
        private String picture;
        public String getPicture() {
            return picture;
        }
    }

    public static UserInfo getUserInfo(Credential credential) throws IOException {
        HttpRequest request = HTTP_TRANSPORT
            .createRequestFactory(credential)
            .buildGetRequest(new GenericUrl(USER_INFO_URI));
        request.getHeaders().setContentType("application/json");
        return request.execute().parseAs(UserInfo.class);
    }

    public void start() throws Exception {
        if (server != null){
            server.start();
        }
    }

    public void join() throws Exception {
        if (server != null){
            server.join();
        }
    }

    @Override
    public void close() throws Exception {
        if (server != null && !server.isStopped()) {
            server.stop();
        }
    }

    public static class Settings {
        URI callbackUri;
        String host;
        int port;
        String principal;
        String keytabPath;
        String clientId;
        String clientSecret;
        boolean enableSpnego;

        public Settings() {
            callbackUri = new GenericUrl(AppSettings.requireProperty(("OAUTH_CALLBACK_URI"))).toURI();
            host = AppSettings.requireProperty("AUTHORIZER_HOST");
            port = Integer.valueOf(AppSettings.requireProperty("AUTHORIZER_PORT"));
            principal = AppSettings.requireProperty("AUTHORIZER_PRINCIPAL");
            keytabPath = AppSettings.requireProperty("AUTHORIZER_KEYTAB");
            clientId = AppSettings.requireProperty("OAUTH_CLIENT_ID");
            clientSecret = AppSettings.requireProperty("OAUTH_CLIENT_SECRET");
            enableSpnego = AppSettings.requireProperty("AUTHORIZER_ENABLE_SPNEGO").equalsIgnoreCase("true");
        }
    }

    public static class CallbackOptions{
        private GoogleAuthorizationCodeFlow flow;
        private RefreshTokenStore db;
        private AbstractEncryptionBackend aead;
        private String redirectUri;
    }

    public static class CallbackServlet extends HttpServlet {
        private CallbackOptions opts;
        public CallbackServlet(CallbackOptions opts) {
            this.opts = opts;
        }

        public void putRefreshToken(String principal, String refreshToken){
            opts.db.putRefreshToken(RefreshToken.create(refreshToken, principal, opts.aead));
        }

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            HttpSession session = req.getSession(false);
            if (session == null){
                resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
            String state = (String) session.getAttribute(STATE_PARAM);
            String stateParam = req.getParameter(STATE_PARAM);
            String authzCode = req.getParameter(CODE_PARAM);
            if (state == null || !state.equals(stateParam)) {
                resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            } else if (authzCode == null) {
                resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                return;
            } else if (req.getUserPrincipal() == null) {
                resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
            session.removeAttribute(STATE_PARAM);

            final TokenResponse tokenResponse = opts.flow
                .newTokenRequest(authzCode)
                .setRedirectUri(opts.redirectUri)
                .execute();

            Credential credential = new Credential
                .Builder(ACCESS_METHOD)
                .build()
                .setFromTokenResponse(tokenResponse);

            UserInfo user = getUserInfo(credential);
            resp.setContentType("text/html");
            PrintWriter w = resp.getWriter();

            // Store Refresh Token for authenticated principal
            putRefreshToken(req.getUserPrincipal().getName(), credential.getRefreshToken());

            Map<String, Object> data = ImmutableMap.<String, Object>builder()
                .put("principal", req.getUserPrincipal().getName())
                .put("email", user.getEmail())
                .put("picture", user.getPicture())
                .build();

            String content = soySauce
                .renderTemplate("Authorizer.Templates.Callback.success")
                .setData(data)
                .renderHtml()
                .get()
                .getContent();
            w.write(content);
        }
    }

    public static class LoginServlet extends HttpServlet {
        private GoogleAuthorizationCodeFlow flow;
        private String redirectUri;

        public LoginServlet(GoogleAuthorizationCodeFlow flow, String redirectUri) {
            this.flow = flow;
            this.redirectUri = redirectUri;
        }

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
            // prevent request forgery
            String state = new BigInteger(130, rng).toString(32);
            req.getSession().setAttribute(STATE_PARAM, state);
            res.sendRedirect(flow
                .newAuthorizationUrl()
                .setRedirectUri(redirectUri)
                .setState(state)
                .build());
        }
    }
}