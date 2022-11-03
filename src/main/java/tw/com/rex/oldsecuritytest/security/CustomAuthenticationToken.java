package tw.com.rex.oldsecuritytest.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

public class CustomAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 9137341564307358208L;

    private Object principal;
    private Object credentials;

    public CustomAuthenticationToken(Object ssoToken) {
        super(null);
        this.credentials = ssoToken;
        super.setAuthenticated(false);
    }

    public CustomAuthenticationToken(Object userDetail, Object ssoToken, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = userDetail;
        this.credentials = ssoToken;
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }

        super.setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        credentials = null;
    }

}
