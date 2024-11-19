package se.digg.eudiw.issuer_tests.controllers;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import jakarta.websocket.server.PathParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestClient;
import org.springframework.web.servlet.view.RedirectView;
import se.digg.eudiw.issuer_tests.config.EudiwConfig;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

@Controller
public class DemoTestsController {
    Logger logger = LoggerFactory.getLogger(DemoTestsController.class);

    final URI callbackDemoAuthFlowUri;
    final URI callbackDemoPreAuthFlowUri;
    final URI authzEndpoint;
    final URI tokenEndpoint;

    Nonce nonce = new Nonce(); // move to request
    CodeVerifier pkceVerifier = new CodeVerifier(); // move to request

	private EudiwConfig eudiwConfig;

    DemoTestsController(@Autowired EudiwConfig eudiwConfig) {
        logger.info("PreAuthController created");
        this.eudiwConfig = eudiwConfig;

        callbackDemoAuthFlowUri = URI.create(String.format("%s/callback-demo-auth", eudiwConfig.getTestServerBaseUrl()));
        callbackDemoPreAuthFlowUri = URI.create(String.format("%s/callback-demo-pre-auth", eudiwConfig.getTestServerBaseUrl()));
        authzEndpoint = URI.create(String.format("%s/oauth2/authorize", eudiwConfig.getIssuerBaseUrl()));
        tokenEndpoint = URI.create(String.format("%s/oauth2/token", eudiwConfig.getIssuerBaseUrl()));

    }

    @GetMapping("/demo")
    public String greeting(@RequestParam(name="name", required=false, defaultValue="World") String name, Model model) {

        List<String> demoCases = List.of("auth-flow", "pre-auth-flow");
        System.out.println(eudiwConfig);
        model.addAttribute("demoCases", demoCases);
        return "demo";
    }

    @GetMapping("/auth-flow")
    public String authFlow(@RequestParam(name="name", required=false, defaultValue="World") String name, Model model) {
        return "auth-flow";
    }

    /**
     * Initialize auth in pre-auth flow
     * @return
     * @throws URISyntaxException
     */
    @GetMapping("/init-auth-flow")
    public RedirectView initAuthFlow() throws URISyntaxException {

        // Generate new random string to link the callback to the authZ request
        State state = new State();

        Scope scope = new Scope();
        scope.add("VerifiablePortableDocumentA1");
        scope.add("openid");
        scope.add("profile");

        AuthenticationRequest request = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                scope,
                new ClientID(eudiwConfig.getClientId()),
                callbackDemoAuthFlowUri)
                .endpointURI(authzEndpoint)
                .state(state)
                .nonce(nonce)
                .codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
                .build();

        String redirectUri = request.toURI().toString();
        logger.info("Redirecting to: " + redirectUri);

        return new RedirectView(redirectUri);
    }

    @GetMapping("/pre-auth-flow")
    public String preAuthFlow(@RequestParam(name="name", required=false, defaultValue="World") String name, Model model) {
        return "pre-auth-flow";
    }

    /**
     * Initialize auth in pre-auth flow
     * @return
     * @throws URISyntaxException
     */
    @GetMapping("/init-pre-auth-flow")
    public RedirectView initPreAuthFlow() throws URISyntaxException {

        // Generate new random string to link the callback to the authZ request
        State state = new State();

       Scope scope = new Scope();
       scope.add("VerifiablePortableDocumentA1");
       scope.add("openid");
       scope.add("profile");

        AuthenticationRequest request = new AuthenticationRequest.Builder(
            new ResponseType("code"),
            scope,
            new ClientID(eudiwConfig.getClientId()),
            callbackDemoPreAuthFlowUri)
            .endpointURI(authzEndpoint)
            .state(state)
            .nonce(nonce)
            .codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
            .build();

        String redirectUri = request.toURI().toString();
        logger.info("Redirecting to: " + redirectUri);
    


        return new RedirectView(redirectUri);
    }

    @GetMapping(value = "/callback-demo-auth", produces = MediaType.TEXT_HTML_VALUE)
    public String welcomeAsHTML(@RequestParam("code") String codeParam, @RequestParam("state") String state, Model model) throws Exception {
          if (pkceVerifier == null) {
              throw new Exception("pkceVerifier is null");
          }
          if (nonce == null) {
              throw new Exception("nonce is null");
          }

          logger.info("code: {}", codeParam);

        AuthorizationCode code = new AuthorizationCode(codeParam);
        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, callbackDemoAuthFlowUri, pkceVerifier);

// The client ID to identify the client at the token endpoint
        ClientID clientID = new ClientID(eudiwConfig.getClientId());

// Make the token request
        TokenRequest request = new TokenRequest(tokenEndpoint, clientID, codeGrant);

        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(request.toHTTPRequest().send());

        if (! tokenResponse.indicatesSuccess()) {
            // We got an error response...
            TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
            return "callback-demo-auth";
        }

        OIDCTokenResponse successResponse = (OIDCTokenResponse)tokenResponse.toSuccessResponse();

// Get the ID and access token, the server may also return a refresh token
        JWT idToken = successResponse.getOIDCTokens().getIDToken();
        AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
        RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();

        RestClient client = RestClient
                .builder()
                .baseUrl(eudiwConfig.getCredentialHost())
                .defaultHeader("Authorization", String.format("Bearer %s", accessToken.getValue()))
                .build();

        String credential = client
                .post()
                .uri(String.format("%s/credential", eudiwConfig.getCredentialHost()))
                .contentType(MediaType.APPLICATION_JSON)
                .body(new HashMap<String, String>())
                .retrieve()
                .body(String.class);

        String[] splittedCredential = credential == null ? new String[]{} : credential.split("~");
        List<String> decodedCredentials = Arrays.stream(splittedCredential).map(c -> {
            try {
                SignedJWT decodedJWT = SignedJWT.parse(c);
                String header = decodedJWT.getHeader().toString();
                String payload = decodedJWT.getPayload().toString();
                return header + payload;
            }
            catch (java.text.ParseException e) {
                PlainJWT plainJWT;

                try {
                    byte[] decodedBytes = Base64.getDecoder().decode(c);

                    return new String(decodedBytes);

                } catch (Exception e2) {
                    // Invalid plain JWT encoding
                    return "Invalid: " + c;
                }

// continue with header and claims extraction...


            }
        }).toList();

        model.addAttribute("idToken", idToken);
        model.addAttribute("accessToken", accessToken.getValue());
        model.addAttribute("refreshToken", refreshToken);

        model.addAttribute("credentialEndpoint", String.format("%s/credential", eudiwConfig.getCredentialHost()));
        model.addAttribute("authHeaderValue", String.format("Bearer %s", accessToken.getValue()));
        model.addAttribute("decodedCredentials", decodedCredentials);
        return "callback-demo-auth";
      }
      


    @GetMapping(value="/callbackdebugtmp", produces = MediaType.TEXT_HTML_VALUE)
    String callback(@PathParam("code") String code, @PathParam("state") String state) throws URISyntaxException {
        logger.info("Callback called with code: " + code + " and state: " + state);
        // The obtained authorisation code
        AuthorizationCode authorizationCode = new AuthorizationCode(code);

        // Make the token request, with PKCE
        TokenRequest tokenRequest = new TokenRequest(
            URI.create(String.format("%s/oauth2/token", eudiwConfig.getIssuerBaseUrl())),
            new ClientID(eudiwConfig.getClientId()),
            new AuthorizationCodeGrant(authorizationCode, callbackDemoAuthFlowUri, pkceVerifier));

        logger.info("Created token request");

        try {
            HTTPRequest tokenHttpRequest = tokenRequest.toHTTPRequest();
            logger.info("send token request to: " + tokenHttpRequest.getURL());
            HTTPResponse httpResponse = tokenHttpRequest.send();

            TokenResponse tokenResponse = TokenResponse.parse(httpResponse);

            if (! tokenResponse.indicatesSuccess()) {
                // The token request failed
                ErrorObject errorObject = tokenResponse.toErrorResponse().getErrorObject();
                throw new RuntimeException(errorObject.toString());
            }

            logger.info("sent token request");
            logger.info("token status code: " + tokenResponse.indicatesSuccess());
            AccessTokenResponse accessToken = tokenResponse.toSuccessResponse();
            String jwt = accessToken.getTokens().getBearerAccessToken().getValue();
            logger.info("token jwt: " + jwt);
            //logger.info("token jwt: " + accessToken.getTokens().getRefreshToken().toString());

            return jwt;
        } catch (Exception e) {
            logger.error("Error: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

}
