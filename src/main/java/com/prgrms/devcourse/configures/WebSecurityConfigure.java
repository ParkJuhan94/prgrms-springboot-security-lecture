package com.prgrms.devcourse.configures;

import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Override
    public void configure(WebSecurity web) {
        // 특정 경로 패턴에 대한 Spring Security 보안 필터 체인을 적용하지 않도록 구성
        web.ignoring().antMatchers("/assets/**", "/h2-console/**");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("user").password("{noop}user123").roles("USER")
            .and()
            .withUser("admin01").password("{noop}admin123").roles("ADMIN")
            .and()
            .withUser("admin02").password("{noop}admin123").roles("ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()    // HTTP 요청에 대한 보안을 구성
                .antMatchers("/me", "/asyncHello", "/someMethod").hasAnyRole("USER", "ADMIN")
                .antMatchers("/admin").access("hasRole('ADMIN') and isFullyAuthenticated()")
                .anyRequest().permitAll() // 위에서 정의되지 않은 모든 요청은 누구나 접근할 수 있도록 허용
                .accessDecisionManager(accessDecisionManager())
                .and()
            .formLogin() // 폼 기반 로그인을 활성화
                .defaultSuccessUrl("/") // 로그인 성공 시 리디렉션되는 기본 URL을 "/" 로 설정
                .permitAll() // 모든 사용자가 로그인 페이지에 접근할 수 있도록 설정
                .and()
            .rememberMe()
                .rememberMeParameter("remember") // default: remember-me, checkbox 등의 이름과 맞춰야 함
                .tokenValiditySeconds(300) // 쿠키의 만료시간 설정(초), default: 14일
                .alwaysRemember(false) // 사용자가 체크박스를 활성화하지 않아도 항상 실행, default: false
                .and()
            .logout()
                .logoutUrl("/logout") // Set custom logout URL
                .logoutSuccessUrl("/")
                .permitAll()
                .and()
            /*
             * HTTP 요청을 HTTPS 요청으로 리다이렉트
             */
            .requiresChannel()
                .anyRequest().requiresSecure()
                .and()
            /*
             * 세션 관리 설정
             */
            .sessionManagement()
                .sessionFixation().changeSessionId() //  세션 고정 공격을 방지하기 위해 새 세션을 생성할 때마다 세션 ID를 변경
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 필요한 경우에만 세션을 생성
                .invalidSessionUrl("/") // 유효하지 않은 세션(예: 만료된 세션)이 감지될 경우 리디렉션
                .maximumSessions(1) // 한 사용자가 동시에 가질 수 있는 최대 세션 수를 제한 -> 동일한 사용자 계정으로 여러 위치에서 동시 로그인을 방지
                    .maxSessionsPreventsLogin(false) // 이미 최대 세션 수에 도달했을 때 추가 로그인을 차단하지 않도록 설정. 새 로그인이 발생하면 가장 오래된 세션을 종료
                    .and()
                .and()
            .httpBasic()
                .and()
            /*
             * 예외처리 핸들러
             */
            .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler());
    }

    @Bean
    public AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<?>> decisionVoters = new ArrayList<>();
        decisionVoters.add(new WebExpressionVoter());
        decisionVoters.add(new OddAdminVoter(new AntPathRequestMatcher("/admin")));
        return new UnanimousBased(decisionVoters);
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain");
            response.getWriter().write("## ACCESS DENIED ##");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }

    @Bean
    @Qualifier("myAsyncTaskExecutor")
    public ThreadPoolTaskExecutor threadPoolTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(3);
        executor.setMaxPoolSize(5);
        executor.setThreadNamePrefix("my-executor-");
        return executor;
    }

    @Bean
    public DelegatingSecurityContextAsyncTaskExecutor taskExecutor(
        @Qualifier("myAsyncTaskExecutor") ThreadPoolTaskExecutor delegate
    ) {
        return new DelegatingSecurityContextAsyncTaskExecutor(delegate);
    }
}
