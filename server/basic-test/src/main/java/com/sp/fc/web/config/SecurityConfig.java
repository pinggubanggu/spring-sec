package com.sp.fc.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


@EnableWebSecurity(debug = true)
// 사전에 권한을 확인하겠다.
@EnableGlobalMethodSecurity(prePostEnabled = true)

// application.yml에서는 USER를 하나만 쓸 수 있다.
// user와 admin의 권한을 가진 USER 구현 및 권한에 따른 url 접근을 위해서
public class SecurityConfig extends
    WebSecurityConfigurerAdapter {

  @Override
  // user와 admin 2개의 User 생성
  // 비밀번호는 encoding 해야 한다.
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
              .withUser(User.builder()
              .username("user2")
                .password(passwordEncoder().encode("2222"))
                .roles("USER")
              ).withUser(User.builder()
                .username("admin")
                .password(passwordEncoder().encode("3333"))
                .roles("ADMIN")
              );
  }

  // 비밀번호를 encoding 하자
  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }


  // 스프링 시큐리티는 처음부터 다 막고 시작한다.
  // 처음의 "/"의 홈페이지가 나오는 거는 다 들어오게 하고 싶다.
  // "/user" url로 들어오면 login 화면을 띄워서 user 권한을 가지고 있는지 확인하여 페이지 노출
  // "/admin" url로 들어오면 login 화면을 띄워서 admin 권한을 가지고 있는지 확인하여 페이지 노출
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests( (requests) ->
            requests.antMatchers("/").permitAll()
                    .anyRequest().authenticated()
    );

    http.formLogin();
    http.httpBasic();

  }
}
