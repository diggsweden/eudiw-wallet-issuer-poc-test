package se.digg.eudiw.issuer_tests.controllers;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
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
public class Test1Controller {
    Logger logger = LoggerFactory.getLogger(Test1Controller.class);

    final URI callbackUri;
    final URI authzEndpoint;
    final URI tokenEndpoint;

    Nonce nonce = new Nonce(); // move to request
    CodeVerifier pkceVerifier = new CodeVerifier(); // move to request

	private EudiwConfig eudiwConfig;

    Test1Controller(@Autowired EudiwConfig eudiwConfig) {
        logger.info("PreAuthController created");
        this.eudiwConfig = eudiwConfig;

        callbackUri = URI.create(String.format("%s/callback-test-1-authorisation-flow", eudiwConfig.getTestServerBaseUrl()));
        authzEndpoint = URI.create(String.format("%s/oauth2/authorize", eudiwConfig.getIssuerBaseUrl()));
        tokenEndpoint = URI.create(String.format("%s/oauth2/token", eudiwConfig.getIssuerBaseUrl()));

    }

    /**
     * Initialize auth in pre-auth flow
     * @return
     * @throws URISyntaxException
     */
    @GetMapping("/start-test-1-authorisation-flow")
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
                callbackUri)
                .endpointURI(authzEndpoint)
                .state(state)
                .nonce(nonce)
                .codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
                .build();

        String redirectUri = request.toURI().toString();
        logger.info("Redirecting to: " + redirectUri);

        return new RedirectView(redirectUri);
    }

    @GetMapping(value = "/callback-test-1-authorisation-flow", produces = MediaType.TEXT_HTML_VALUE)
    public String welcomeAsHTML(@RequestParam("code") String codeParam, @RequestParam("state") String state, Model model) throws Exception {
          if (pkceVerifier == null) {
              throw new Exception("pkceVerifier is null");
          }
          if (nonce == null) {
              throw new Exception("nonce is null");
          }

          logger.info("code: {}", codeParam);

        AuthorizationCode code = new AuthorizationCode(codeParam);
        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, callbackUri, pkceVerifier);

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

}
