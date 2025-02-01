package nextstep.security.authentication;

public interface UserDetailsService {

    UserDetails loadUserByUsername(String username);
}
