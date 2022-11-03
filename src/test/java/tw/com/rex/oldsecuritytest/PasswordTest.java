package tw.com.rex.oldsecuritytest;

import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordTest {

    @Test
    public void test() {
        String oauth = new BCryptPasswordEncoder().encode("oauth");
        System.out.println(oauth);
    }

}
