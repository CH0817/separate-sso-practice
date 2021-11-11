package tw.com.rex.separatessopractice.config;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
import org.jasig.cas.client.validation.Cas20ProxyTicketValidator;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import tw.com.rex.separatessopractice.security.CustomAuthenticationSuccessHandler;
import tw.com.rex.separatessopractice.security.CustomerCasAuthenticationEntryPoint;

import javax.servlet.Filter;
import java.util.Arrays;
import java.util.Collections;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @NonNull
    private final AuthenticationUserDetailsService<CasAssertionAuthenticationToken> userDetailsService;
    @Value("${frontend-url}")
    private String frontendUrl;
    @Value("${app.login-url}")
    private String appLoginUrl;
    @Value("${sso.server-url}")
    private String ssoServerUrl;
    @Value("${sso.logout-url}")
    private String ssoLogoutUrl;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(casAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().configurationSource(corsConfigurationSource()).and()
            .csrf().disable()
            .authorizeRequests().anyRequest().authenticated().and()
            .exceptionHandling().authenticationEntryPoint(casAuthenticationEntryPoint()).and()
            .addFilter(casAuthenticationFilter())
            .addFilterBefore(casLogoutFilter(), LogoutFilter.class)
            .addFilterBefore(singleSignOutFilter(), CasAuthenticationFilter.class);
    }

    /**
     * 跨域請求設定
     *
     * @return CorsConfigurationSource
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // 允許跨域請求的 client url
        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:8100"));
        // 允許跨域請求的 method
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        // 允許跨域請求的 header
        configuration.setAllowedHeaders(Arrays.asList("Content-Type", "Authorization", "X-CSRF-TOKEN"));
        // 是否允許請求帶有驗證訊息
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public AuthenticationProvider casAuthenticationProvider() {
        CasAuthenticationProvider provider = new CasAuthenticationProvider();
        provider.setAuthenticationUserDetailsService(userDetailsService);
        provider.setServiceProperties(serviceProperties());
        provider.setTicketValidator(ticketValidator());
        provider.setKey("PRACTICE_KEY");
        return provider;
    }

    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties properties = new ServiceProperties();
        properties.setService(appLoginUrl);
        properties.setSendRenew(true);
        return properties;
    }

    private TicketValidator ticketValidator() {
        return new Cas20ProxyTicketValidator(ssoServerUrl);
    }

    private AuthenticationEntryPoint casAuthenticationEntryPoint() {
        return new CustomerCasAuthenticationEntryPoint();
    }

    @Bean
    public Filter casAuthenticationFilter() throws Exception {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManager());
        filter.setAuthenticationSuccessHandler(casAuthenticationSuccessHandler());
        return filter;
    }

    @Bean
    public AuthenticationSuccessHandler casAuthenticationSuccessHandler() {
        return new CustomAuthenticationSuccessHandler();
    }

    @Bean
    public LogoutFilter casLogoutFilter() {
        // TODO 前端能知道是否已經登出？ frontendUrl URL 加參數？
        return new LogoutFilter(ssoLogoutUrl + "?service=" + frontendUrl, new SecurityContextLogoutHandler());
    }

    @Bean
    public SingleSignOutFilter singleSignOutFilter() {
        SingleSignOutFilter filter = new SingleSignOutFilter();
        filter.setIgnoreInitConfiguration(true);
        return filter;
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public SingleSignOutHttpSessionListener SingleSignOutHttpSessionListener() {
        return new SingleSignOutHttpSessionListener();
    }

}
