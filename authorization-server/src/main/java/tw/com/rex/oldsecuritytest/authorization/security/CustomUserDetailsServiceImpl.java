package tw.com.rex.oldsecuritytest.authorization.security;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component("customUserDetailsService")
public class CustomUserDetailsServiceImpl implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        CustomUserDetails userDetails = new CustomUserDetails();
        userDetails.setUserId("cn");
        userDetails.setUsername("sn");
        userDetails.setEmployeeNumber("employeeNumber");
        userDetails.setDisplayName("displayName");
        userDetails.setDepartmentCode("departmentNumber");
        userDetails.setDepartmentName("department");
        userDetails.setDescription("description");
        userDetails.setAuthorities(AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
        return userDetails;
    }

}
