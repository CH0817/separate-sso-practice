package tw.com.rex.separatessopractice.security;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 自訂 CAS entry point
 */
@Slf4j
@Data
public class CustomerCasAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public final void commence(final HttpServletRequest request,
                               final HttpServletResponse response,
                               final AuthenticationException authenticationException) {
        // 傳 401 回去，
        Cookie[] cookies = request.getCookies();
        System.out.println("========");
        System.out.println(cookies.length);
        for (Cookie cookie : cookies) {
            System.out.println(cookie.getName());
            System.out.println(cookie.getValue());
        }
        System.out.println("========");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

}
