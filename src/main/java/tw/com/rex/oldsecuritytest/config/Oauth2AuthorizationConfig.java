package tw.com.rex.oldsecuritytest.config;

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
import tw.com.rex.oldsecuritytest.security.CustomTokenGranter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Configuration
@EnableAuthorizationServer
public class Oauth2AuthorizationConfig extends AuthorizationServerConfigurerAdapter {

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
                // client ?????? (????????????)
                .secret(passwordEncoder.encode("oauth"))
                // ?????????????????? resource id
                .resourceIds("oauth-resource")
                // ?????????????????????
                .authorizedGrantTypes("authorization_code", "password", "client_credentials", "refresh_token", "custom")
                // ??????????????????
                .authorities("ROLE_ADMIN", "ROLE_USER")
                // ????????????
                .scopes("all")
                // token ????????????
                .accessTokenValiditySeconds(6000)
                // ?????? token ????????????
                .refreshTokenValiditySeconds(6000)
                // client ????????????
                .redirectUris("https://www.google.com");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints
                // ????????????????????????????????????
                .authenticationManager(authenticationManager)
                // ???????????????????????? token
                .userDetailsService(userDetailsService)
                .tokenGranter(tokenGranter(endpoints));
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        // ???????????? resource server ??????????????????????????? (403) (/oauth/check_token)
        security.checkTokenAccess("isAuthenticated()")
                .passwordEncoder(passwordEncoder);
    }

    private TokenGranter tokenGranter(final AuthorizationServerEndpointsConfigurer endpoints) {
        List<TokenGranter> granters = new ArrayList<>(Collections.singletonList(endpoints.getTokenGranter()));

        AuthorizationServerTokenServices tokenServices = endpoints.getTokenServices();
        ClientDetailsService clientDetailsService = endpoints.getClientDetailsService();
        OAuth2RequestFactory requestFactory = endpoints.getOAuth2RequestFactory();

        // ???????????????
        granters.add(new AuthorizationCodeTokenGranter(tokenServices, new InMemoryAuthorizationCodeServices(), clientDetailsService, requestFactory));
        // ????????????
        granters.add(new ResourceOwnerPasswordTokenGranter(authenticationManager, tokenServices, clientDetailsService, requestFactory));
        // ??????????????????
        granters.add(new RefreshTokenGranter(tokenServices, clientDetailsService, requestFactory));
        // ????????????
        granters.add(new ImplicitTokenGranter(tokenServices, clientDetailsService, requestFactory));
        // ???????????????
        granters.add(new ClientCredentialsTokenGranter(tokenServices, clientDetailsService, requestFactory));
        // ????????????
        granters.add(new CustomTokenGranter(tokenServices, clientDetailsService, requestFactory, "custom", authenticationManager));
        return new CompositeTokenGranter(granters);
    }

}
