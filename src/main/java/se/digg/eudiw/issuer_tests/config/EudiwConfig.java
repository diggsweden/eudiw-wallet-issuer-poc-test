package se.digg.eudiw.issuer_tests.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix="eudiw")
@Configuration
@Component 
public class EudiwConfig {

    private String issuerBaseUrl;

    private String credentialHost;

    private String clientId;

    private String testServerBaseUrl;

    public String getIssuerBaseUrl() {
        return issuerBaseUrl;
    }

    public void setIssuerBaseUrl(String issuerBaseUrl) {
        this.issuerBaseUrl = issuerBaseUrl;
    }

    public String getCredentialHost() {
        return credentialHost;
    }

    public void setCredentialHost(String credentialHost) {
        this.credentialHost = credentialHost;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getTestServerBaseUrl() {
        return testServerBaseUrl;
    }

    public void setTestServerBaseUrl(String testServerBaseUrl) {
        this.testServerBaseUrl = testServerBaseUrl;
    }

    @Override
    public String toString() {
        return "EudiwConfig{" +
                "issuerBaseUrl='" + issuerBaseUrl + '\'' +
                ", credentialHost='" + credentialHost + '\'' +
                ", clientId='" + clientId + '\'' +
                ", testServerBaseUrl='" + testServerBaseUrl + '\'' +
                '}';
    }
}