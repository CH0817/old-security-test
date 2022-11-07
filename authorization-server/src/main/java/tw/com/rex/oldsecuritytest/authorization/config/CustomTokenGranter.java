package tw.com.rex.oldsecuritytest.authorization.config;

import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

@AllArgsConstructor
public class CustomTokenGranter implements TokenGranter {

    private ClientDetailsService clientDetailsService;
    private AuthorizationServerTokenServices tokenService;
    private OAuth2RequestFactory requestFactory;

    @Override
    public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
        // FIXME 先驗證再產生 token
        // InvalidClientException
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(tokenRequest.getClientId());
        return getAccessToken(clientDetails, tokenRequest);
    }

    protected OAuth2AccessToken getAccessToken(ClientDetails client, TokenRequest tokenRequest) {
        return tokenService.createAccessToken(getOAuth2Authentication(client, tokenRequest));
    }

    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        OAuth2Request storedOAuth2Request = requestFactory.createOAuth2Request(client, tokenRequest);
        return new OAuth2Authentication(storedOAuth2Request, null);
    }

}
