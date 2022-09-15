package vince.com.security.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import vince.com.security.auth.ApplicationUserService;
import vince.com.security.jwt.JwtUsernameAndPasswordAuthenticationFilter;

import static vince.com.security.security.ApplicationUserRole.*;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final AuthenticationConfiguration authenticationConfiguration;

    @Autowired
    public ApplicationSecurityConfig (PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService, AuthenticationConfiguration authenticationConfiguration) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.authenticationConfiguration = authenticationConfiguration;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager()))
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
//                .antMatchers( HttpMethod.DELETE, "/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())
//                .antMatchers( HttpMethod.POST, "/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())
//                .antMatchers( HttpMethod.PUT, "/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                .anyRequest()
                .authenticated();
//                .formLogin()
//                    .loginPage("/login")
//                    .permitAll()
//                    .defaultSuccessUrl("/courses", true)
//                    .passwordParameter("password")
//                    .usernameParameter("username")
//                .and()
//                .rememberMe()
//                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//                    .key("somethingverysecured")
//                    .rememberMeParameter("remember-me")
//                .and()
//                .logout().logoutUrl("/logout")
//                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
//                    .clearAuthentication(true)
//                    .clearAuthentication(true)
//                    .invalidateHttpSession(true)
//                .deleteCookies("JSESSIONID", "remember-me")
//                .logoutSuccessUrl("/login");
//                .httpBasic();
        return http.build();

    }

//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails vinceUser = User.builder()
//                .username("vince")
//                .password(passwordEncoder.encode("password"))
////                .roles(STUDENT.name()) // ROLE_STUDENT
//                .authorities(STUDENT.getGrantedAuthority())
//                .build();
//
//        //Create Admin role
//        UserDetails lisaUser = User.builder()
//                .username("lisa")
//                .password(passwordEncoder.encode("password123"))
////                .roles(ADMIN.name()) // Admin_Role
//                .authorities(ADMIN.getGrantedAuthority())
//                .build();
//
//        UserDetails tomUser = User.builder()
//                .username("tom")
//                .password(passwordEncoder.encode("password123"))
////                .roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
//                .authorities(ADMINTRAINEE.getGrantedAuthority())
//                .build();
//
//        return new InMemoryUserDetailsManager(
//                vinceUser,
//                lisaUser,
//                tomUser
//        );

    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());

    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}



