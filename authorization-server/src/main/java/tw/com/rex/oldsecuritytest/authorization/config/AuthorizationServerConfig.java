package tw.com.rex.oldsecuritytest.authorization.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        InMemoryClientDetailsServiceBuilder builder = clients.inMemory();
        builder
                // client id
                .withClient("oauth")
                // client 密鑰 (加密過的)
                .secret(passwordEncoder.encode("oauth"))
                // 授權後可用的 resource id
                .resourceIds("oauth-resource")
                // 可用的授權模式
                .authorizedGrantTypes("authorization_code", "password", "refresh_token")
                // 可授權的角色
                .authorities("ROLE_ADMIN", "ROLE_USER")
                // 授權範圍
                .scopes("all")
                // token 有效時間
                .accessTokenValiditySeconds(6000)
                // 刷新 token 有效時間
                .refreshTokenValiditySeconds(6000)
                // client 回調網址
                .redirectUris("https://www.google.com");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints
                // 不加這段密碼模式無法使用
                .authenticationManager(authenticationManager)
                // 不加這段無法刷新 token
                .userDetailsService(userDetailsService)
                .tokenGranter(tokenGranter(endpoints));
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        // 不加這段 resource server 無法存取該資源權限 (403) (/oauth/check_token)
        security.checkTokenAccess("isAuthenticated()")
                .passwordEncoder(passwordEncoder);
    }

    private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
        ClientDetailsService clientDetailsService = endpoints.getClientDetailsService();
        AuthorizationServerTokenServices tokenServices = endpoints.getTokenServices();
        OAuth2RequestFactory requestFactory = endpoints.getOAuth2RequestFactory();
        return new CustomTokenGranter(clientDetailsService, tokenServices, requestFactory);
    }

}
