package tw.com.rex.oldsecuritytest.resource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().authorizeRequests().anyRequest().access("#oauth2.hasAnyScope('all')");
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.resourceId("oauth-resource");
    }

    @Bean
    public RemoteTokenServices remoteTokenServices() {
        RemoteTokenServices services = new RemoteTokenServices();
        services.setCheckTokenEndpointUrl("http://localhost:8880/oauth/check_token");
        services.setClientId("oauth");
        services.setClientSecret("oauth");
        return services;
    }

}
