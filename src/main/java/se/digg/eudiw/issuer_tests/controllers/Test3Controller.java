package se.digg.eudiw.issuer_tests.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
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
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.DefaultUriBuilderFactory;
import se.digg.eudiw.issuer_tests.config.EudiwConfig;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.stream.Collectors;

@Controller
public class Test3Controller {
    Logger logger = LoggerFactory.getLogger(Test3Controller.class);

    final URI callbackUri;
    final URI authzEndpoint;
    final URI tokenEndpoint;

    Nonce nonce = new Nonce(); // move to request
    CodeVerifier pkceVerifier = new CodeVerifier(); // move to request
    private final ObjectMapper objectMapper = new ObjectMapper();

    private EudiwConfig eudiwConfig;

    private final RestTemplate restTemplate;

    Test3Controller(@Autowired EudiwConfig eudiwConfig, @Autowired RestTemplate restTemplate) {
        logger.info("PreAuthController created");
        this.eudiwConfig = eudiwConfig;

        callbackUri = URI.create(String.format("%s/callback-test-3-par", eudiwConfig.getTestServerBaseUrl()));
        authzEndpoint = URI.create(String.format("%s/oauth2/par", eudiwConfig.getIssuerBaseUrl()));
        tokenEndpoint = URI.create(String.format("%s/oauth2/token", eudiwConfig.getIssuerBaseUrl()));

        this.restTemplate = restTemplate;
        // This allows us to read the response more than once - Necessary for debugging.
        restTemplate.setRequestFactory(new BufferingClientHttpRequestFactory(restTemplate.getRequestFactory()));

        // disable default URL encoding
        DefaultUriBuilderFactory uriBuilderFactory = new DefaultUriBuilderFactory();
        uriBuilderFactory.setEncodingMode(DefaultUriBuilderFactory.EncodingMode.VALUES_ONLY);
        restTemplate.setUriTemplateHandler(uriBuilderFactory);
    }

    /**
     * Initialize auth in pre-auth flow
     * @return
     * @throws URISyntaxException
     */
    @GetMapping("/start-test-3-par")
    public RedirectView initAuthFlow() throws URISyntaxException, JsonProcessingException {

        // Generate new random string to link the callback to the authZ request
        State state = new State();

        Scope scope = new Scope();
        scope.add("eu.europa.ec.eudi.pid.1");
        scope.add("openid");

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.put("scope", List.of(scope.toString()));
        params.put("response_type", List.of("code"));
        params.put("redirect_uri", List.of(callbackUri.toString()));
        params.put("state", List.of(state.getValue()));
        params.put("code_challenge_method", List.of(CodeChallengeMethod.S256.getValue()));
        params.put("code_challenge", List.of(CodeChallenge.compute(CodeChallengeMethod.S256, pkceVerifier).getValue()));
        params.put("nonce", List.of(nonce.getValue()));
        params.put("client_id", List.of(eudiwConfig.getClientId()));

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<Map> request = new HttpEntity<>(params, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(authzEndpoint, request, Map.class);
        logger.info("RESPONSE: {}", response);
        String requestUri = (String) response.getBody().get("request_uri");
        String authRedirectUri = String.format("%s/oauth2/authorize?request_uri=%s", eudiwConfig.getIssuerBaseUrl(), requestUri);
        logger.info("Redirecting to: " + authRedirectUri);

        return new RedirectView(authRedirectUri);
    }

    @GetMapping(value = "/callback-test-3-par", produces = MediaType.TEXT_HTML_VALUE)
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
        logger.info("codeGrant: {}", codeGrant.toParameters().entrySet().stream().map(entry -> String.format("%s: %s", entry.getKey(), entry.getValue().stream().map(String::valueOf)
                .collect(Collectors.joining("-", "{", "}")))).collect(Collectors.joining(" ")));

// The client ID to identify the client at the token endpoint
        ClientID clientID = new ClientID(eudiwConfig.getClientId());

// Make the token request
        TokenRequest request = new TokenRequest(tokenEndpoint, clientID, codeGrant);

        logger.info("TokenRequest: {} {} {}", tokenEndpoint, clientID, codeGrant);

        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(request.toHTTPRequest().send());

        if (! tokenResponse.indicatesSuccess()) {
            // We got an error response...
            TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
            logger.error("TokenErrorResponse: {}", errorResponse.toJSONObject());

            return "callback-demo-auth";
        }

        OIDCTokenResponse successResponse = (OIDCTokenResponse)tokenResponse.toSuccessResponse();

// Get the ID and access token, the server may also return a refresh token
        JWT idToken = successResponse.getOIDCTokens().getIDToken();
        AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
        RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();

        logger.info("OIDCTokenResponse: idToken: {} accessToken: {} refreshToken: {}", idToken, accessToken, refreshToken);

        RestClient client = RestClient
                .builder()
                .baseUrl(eudiwConfig.getCredentialHost())
                .defaultHeader("Authorization", String.format("Bearer %s", accessToken.getValue()))
                .build();

        String credential = client
                .post()
                .uri(String.format("%s/credential", eudiwConfig.getCredentialHost()))
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("format", "vc+sd-jwt", "vct", "urn:eu.europa.ec.eudi:pid:1", "proof", Map.of("proof_type", "jwt", "jwt", "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiUGJqb1lZc1FORHhhUjFSNzZsOVFfOVJ3emJkRjAtNzB4V1dHRFlPNU9iTSIsInkiOiI4U2lyMFJTS0J1Y1JQa0VCb3R5VEM3Vm1LcFQ5XzNBd0dTTE5UZ2F2YVZVIn19.eyJpc3MiOiJ3YWxsZXQtZGV2IiwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIuZXVkaXcuZGV2Iiwibm9uY2UiOiJtZlhVR2R3alhKUm5wdzgwNmdvTVpnIiwiaWF0IjoxNzM4MzMwNjUyfQ.RHdzk6m5sOIvxonRHJj9cnyEl5PFJq0z_sg46HtNJ52mZEDfQTDBWJQvyzwslCFropoFbd0BiRL61WTxyx6zTQ")))
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
