package tw.com.rex.oldsecuritytest.authorization.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import tw.com.rex.oldsecuritytest.authorization.security.CustomTokenGranter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
                .authorizedGrantTypes("authorization_code", "password", "client_credentials", "refresh_token", "custom")
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

    private TokenGranter tokenGranter(final AuthorizationServerEndpointsConfigurer endpoints) {
        List<TokenGranter> granters = new ArrayList<>(Collections.singletonList(endpoints.getTokenGranter()));

        AuthorizationServerTokenServices tokenServices = endpoints.getTokenServices();
        ClientDetailsService clientDetailsService = endpoints.getClientDetailsService();
        OAuth2RequestFactory requestFactory = endpoints.getOAuth2RequestFactory();

        // 授權碼模式
        granters.add(new AuthorizationCodeTokenGranter(tokenServices, new InMemoryAuthorizationCodeServices(), clientDetailsService, requestFactory));
        // 密碼模式
        granters.add(new ResourceOwnerPasswordTokenGranter(authenticationManager, tokenServices, clientDetailsService, requestFactory));
        // 刷新令牌模式
        granters.add(new RefreshTokenGranter(tokenServices, clientDetailsService, requestFactory));
        // 簡化模式
        granters.add(new ImplicitTokenGranter(tokenServices, clientDetailsService, requestFactory));
        // 客戶端模式
        granters.add(new ClientCredentialsTokenGranter(tokenServices, clientDetailsService, requestFactory));
        // 自訂模式
        granters.add(new CustomTokenGranter(tokenServices, clientDetailsService, requestFactory, "custom", authenticationManager));

        return new CompositeTokenGranter(granters);
    }

    @EventListener
    public void authorizationSuccessListener(AuthenticationSuccessEvent event) {
        // 監聽 authorization success event
        System.out.println("authorization success");
    }

    @EventListener
    public void authorizationFailureListener(AbstractAuthenticationFailureEvent event) {
        // 監聽 authorization failure event
        System.out.println("authorization failure");
    }

}
