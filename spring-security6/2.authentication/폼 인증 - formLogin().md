
#### 폼 인증의 흐름

client의 요청 -> 권한 검사 필터 (AuthorizationFilter) -> 접근 예외 발생 (AccessDeniedException) -> 예외 처리 필터 (ExceptionTraslationFilter) -> 인증 시작 (AuthenticationEntryPoint) -> 로그인 페이지 redirect

#### formLogin() API

```
.formLogin(form -> form  
        .loginPage("/loginPage")  
        .loginProcessingUrl("/loginProc")  
        .defaultSuccessUrl("/", false) // alwaysUse의 기본값은 false        .failureUrl("/failed")  
        .usernameParameter("userId")  
        .passwordParameter("passwd")  
        .successHandler(((request, response, authentication) -> {  
            System.out.println("authentication : " + authentication);  
            response.sendRedirect("/home");  
        }))  
        .failureHandler((request, response, exception) -> {  
            System.out.println("exception : " + exception.getMessage());  
            response.sendRedirect("/login");  
        })  
        .permitAll());
```

AbstractAuthenticationFilterConfigurer
