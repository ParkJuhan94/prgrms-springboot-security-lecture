package com.prgrms.devcourse.configures;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends
    WebSecurityConfigurerAdapter {    // Spring Security 설정을 커스터마이징하기 위해 WebSecurityConfigurerAdapter 클래스를 확장


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        super.configure(auth);
    }

    @Override
    public void configure(WebSecurity web) {
        // 특정 경로 패턴(/assets/**)에 대한 Spring Security 보안 필터 체인을 적용하지 않도록 구성합니다.
        // 주로 정적 리소스(이미지, CSS, JavaScript 등)에 사용됩니다.
        web.ignoring().antMatchers("/assets/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/me").hasAnyRole("USER", "ADMIN")
                .anyRequest().permitAll()
                .and()
            .formLogin()
                .defaultSuccessUrl("/")
                .permitAll()
                .and()
        ;
//          authorizeRequests():HTTP 요청에 대한 보안을 구성하기 시작합니다.
//          .antMatchers("/me").hasAnyRole("USER", "ADMIN"):URL 경로가 "/me" 인 경우, "USER" 또는 "ADMIN" 역할을 가진 사용자만 접근할 수 있도록 설정합니다.
//          .anyRequest().permitAll():위에서 정의되지 않은 모든 요청은 누구나 접근할 수 있도록 허용합니다.
//          formLogin():폼 기반 로그인을 활성화합니다.
//          .defaultSuccessUrl("/"):로그인 성공 시 리디렉션되는 기본 URL을 "/" 로 설정합니다.
//          .permitAll():모든 사용자가 로그인 페이지에 접근할 수 있도록 설정합니다.
    }

}
