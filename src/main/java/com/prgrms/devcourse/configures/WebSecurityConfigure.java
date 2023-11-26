package com.prgrms.devcourse.configures;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {
    private PrgrmsUserDetailsService prgrmsUserDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth.inMemoryAuthentication()
            .withUser("user").password("{noop}user123").roles("USER")
            .and()
            .withUser("admin").password("{noop}adnmin123").roles("ADMIN");
    }

    @Override
    public void configure(WebSecurity web) {
        // 특정 경로 패턴에 대한 Spring Security 보안 필터 체인을 적용하지 않도록 구성합니다.
        web.ignoring().antMatchers("/assets/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()    // authorizeRequests():HTTP 요청에 대한 보안을 구성하기 시작합니다.
                .antMatchers("/me").hasAnyRole("USER", "ADMIN")
                .anyRequest().permitAll() // .anyRequest().permitAll():위에서 정의되지 않은 모든 요청은 누구나 접근할 수 있도록 허용
                .and()
            .formLogin() // formLogin():폼 기반 로그인을 활성화
                .defaultSuccessUrl("/") // .defaultSuccessUrl("/"):로그인 성공 시 리디렉션되는 기본 URL을 "/" 로 설정
                .permitAll() // .permitAll():모든 사용자가 로그인 페이지에 접근할 수 있도록 설정
                .and()
            .rememberMe()
                .rememberMeParameter("remember") // default: remember-me, checkbox 등의 이름과 맞춰야 함
                .tokenValiditySeconds(300) // 쿠키의 만료시간 설정(초), default: 14일
                .alwaysRemember(false) // 사용자가 체크박스를 활성화하지 않아도 항상 실행, default: false
                .userDetailsService(prgrmsUserDetailsService) // 기능을 사용할 때 사용자 정보가 필요함. 반드시 이 설정 필요함.
                .and()
            .logout()
                .logoutUrl("/logout") // Set custom logout URL
                .logoutSuccessUrl("/") // Redirect to "/" after logout
                .permitAll()
                .and()
        ;
    }

}
