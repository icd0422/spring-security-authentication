package nextstep.security.authentication;

import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Map;

public class FormLoginInterceptor implements HandlerInterceptor {
    public static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";

    private final UserDetailsService userDetailsService;

    public FormLoginInterceptor(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        try {
            Map<String, String[]> parameterMap = request.getParameterMap();
            String username = parameterMap.get("username")[0];
            String password = parameterMap.get("password")[0];


            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (!userDetails.getPassword().equals(password)) {
                throw new AuthenticationException();
            }

            HttpSession session = request.getSession();
            session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, userDetails);

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }

        return false;
    }
}
