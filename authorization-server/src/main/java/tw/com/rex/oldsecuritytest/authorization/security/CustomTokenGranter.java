package tw.com.rex.oldsecuritytest.authorization.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 自定義授權模式
 */
public class CustomTokenGranter extends AbstractTokenGranter {

    private Logger logger = LoggerFactory.getLogger(CustomTokenGranter.class);

    private final AuthenticationManager authenticationManager;

    public CustomTokenGranter(AuthorizationServerTokenServices tokenServices,
                              ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory,
                              String grantType, AuthenticationManager authenticationManager) {
        super(tokenServices, clientDetailsService, requestFactory, grantType);
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        Map<String, String> parameters = new LinkedHashMap<>(tokenRequest.getRequestParameters());
        String ssoToken = parameters.get("SSO-TOKEN");
        logger.info("SSO-TOKEN: {}", ssoToken);
        if (!StringUtils.hasText(ssoToken)) {
            throw new InvalidGrantException("請求未包含 SSO-TOKEN 參數");
        }
        CustomAuthenticationToken customAuthenticationToken = new CustomAuthenticationToken(ssoToken);
        // 沒有這段 CustomAuthenticationProvider 不會起作用
        Authentication authenticate = authenticationManager.authenticate(customAuthenticationToken);
        if (Objects.isNull(authenticate)) {
            throw new InvalidGrantException("sso token 驗證失敗");
        }
        OAuth2Request storedOAuth2Request = getRequestFactory().createOAuth2Request(client, tokenRequest);
        return new OAuth2Authentication(storedOAuth2Request, customAuthenticationToken);
    }

}
