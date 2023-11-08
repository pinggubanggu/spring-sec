package com.sp.fc.web.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

  @RequestMapping("/")
  public String index() {
    return "홈페이지";
  }

  // 권한정보를 뽑아 볼 수 있다.
  @RequestMapping("/auth")
  public Authentication auth() {
    return SecurityContextHolder.getContext()
            .getAuthentication();
  }

  // ** 사용자와 관리자의 페이지를 다르게 띄워 보자

  // USER 권한이 있어야만 "/user"에 접근 할 수 있다.
  @PreAuthorize("hasAnyAuthority('ROLE_USER')")
  @RequestMapping("/user")
  public SecurityMessage user() {
    return SecurityMessage.builder()
            .auth(SecurityContextHolder.getContext().getAuthentication())
            .message("user 정보")
            .build();
  }

  @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
  @RequestMapping("/admin")
  public SecurityMessage admin() {
    return SecurityMessage.builder()
        .auth(SecurityContextHolder.getContext().getAuthentication())
        .message("admin 정보")
        .build();
  }
}
