# SpringBoot实现JwtToken

> [start.spring.io](!https://start.spring.io/)新建SpringBoot项目，添加SpringWeb,SpringSecurtiry依赖

## 实现步骤如下：

- 建立HelloController，使用@RestController进行注解，建立World方法，使用RequestMapping注解，指定名称为World

  ```java
  @RestController
  public class HelloController {
      @RequestMapping("/hello")
      public String world(){
          return "Hello, World!";
      }
  }
  ```

  编译运行，浏览器打开页面 http://localhost/hello后会自动跳转至登录页，输入用户名和密码后跳转回页面，显示为Hello,World.
  注：用户名为user,密码在页面中

- 建立SecurityConfig配置类， 继承自WebSecurityConfigurerAdapter，用于实现自定义认证等功能

  ```java
  @EnableWebSecurity
  public class SecurityConfig extends WebSecurityConfigurerAdapter {
      @Autowired
      private CustomUserDetailsService userDetailsService;
  
      @Override
      protected void configure(AuthenticationManagerBuilder auth) throws Exception {
          auth.userDetailsService(userDetailsService);
      }
  
      @Bean
      public PasswordEncoder passwordEncoder(){
          return NoOpPasswordEncoder.getInstance();
      }
  }
  ```

  注意：passwordEncoder使用了@Bean注解，没有这个方法的情况下会报错。这里的意思是使用不加密的密码，目前不推荐。

  

- 建立CustomUserDetailsService服务类，实现认证逻辑。

  ```java
  @Service
  public class CustomUserDetailsService implements UserDetailsService {
      @Override
      public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
          return new User("foo", "foo", new ArrayList<>());
      }
  }
  ```

- 添加jjwt依赖

  ```xml
  <dependency>
      <groupId>io.jsonwebtoken</groupId>
      <artifactId>jjwt</artifactId>
      <version>0.9.1</version>
  </dependency>
  ```

  

- 添加JwtUtil类，实现JWTToken各种操作，如生成，验证，取得用户名

  ```java
  @Service
  public class JwtUtil {
      private String SECRET_KEY="JwtTokenKey";
  
      public String extractUserName(String token){
          return extractClaim(token, Claims::getSubject);
      }
  
      public Date extractExpiration(String token){
          return extractClaim(token, Claims::getExpiration);
      }
  
      public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
          final Claims claims=extractAllClaims(token);
          return claimsResolver.apply(claims);
      }
  
      private Claims extractAllClaims(String token){
          return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
      }
  
      private Boolean isTokenExpired(String token){
          return extractExpiration(token).before(new Date());
      }
  
      public String generateToken(UserDetails userDetails){
          Map<String,Object> claims=new HashMap<>();
          return createToken(claims, userDetails.getUsername());
      }
  
      private String createToken(Map<String, Object> claims, String subject){
          return Jwts.builder()
                  .setClaims(claims)
                  .setSubject(subject)
                  .setIssuedAt(new Date(System.currentTimeMillis()))
                  .setExpiration(new Date(System.currentTimeMillis()+1000*60*60*10))
                  .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                  .compact();
      }
  
      public Boolean validateToken(String token, UserDetails userDetails){
          final String userName=extractUserName(token);
          return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
      }
  }
  ```

  

- 添加认证请求和回应Dto

  认证请求：AuthenticationRequest

  ```java
  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  @Builder
  public class AuthenticationRequest {
      private String username;
      private String password;
  }
  ```

  认证回应

  ```java
  @DataAuthenticationResponse
  @AllArgsConstructor
  public class AuthenticationResponse {
      private final String token;
  }
  ```

- HelloController中添加认证方法

  ```java
  @Autowired
  private AuthenticationManager authenticationManager;
  
  @Autowired
  private CustomUserDetailsService userDetailsService;
  @Autowired
  private JwtUtil jwtTokenUtil;
  
  @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
  public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
      try {
          authenticationManager.authenticate(
              new UsernamePasswordAuthenticationToken(
                  authenticationRequest.getUsername(),
                  authenticationRequest.getPassword()
              )
          );
      } catch (BadCredentialsException e) {
          throw new Exception("错误用户名或密码！", e);
      }
  
      final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
      final String jwt = jwtTokenUtil.generateToken(userDetails);
  
      return ResponseEntity.ok(new AuthenticationResponse(jwt));
  }
  ```

- 修改SecurityConfig中configuration(HttpSecurity http)方法,去掉认证路由过滤，添加JWT拦截

  ```java
  @Override
  protected void configure(HttpSecurity http) throws Exception {
      http
          .csrf().disable()				//禁用cros
          .authorizeRequests().antMatchers("/authenticate").permitAll()	//过滤认证页
          .anyRequest().authenticated();	//其他页面需要验证
  }
  ```

  

- SecurityConfig中重写 authenticationManagerBean()方法,指定@Bean注解，否则认证中的authenticationManager注入会报错

  ```java
  @Override
  @Bean
  public AuthenticationManager authenticationManagerBean() throws Exception {
      return super.authenticationManagerBean();
  }
  ```

- 添加JwtRequestFilter，进行 JWT验证

  ```java
  @Component
  public class JwtRequestFilter extends OncePerRequestFilter {
      @Autowired
      private CustomUserDetailsService userDetailsService;
      @Autowired
      private JwtUtil jwtUtil;
  
      @Override
      protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
          final String authorizationHeader=httpServletRequest.getHeader("Authorization");
  
          String username=null;
          String jwt=null;
          if(authorizationHeader!=null && authorizationHeader.startsWith("Bearer ")){
              jwt=authorizationHeader.substring(7);
              username=jwtUtil.extractUserName(jwt);
          }
  
          if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null){
              UserDetails userDetails=this.userDetailsService.loadUserByUsername(username);
              if(jwtUtil.validateToken(jwt, userDetails)){
                  UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken=new UsernamePasswordAuthenticationToken(
                          userDetails, null, userDetails.getAuthorities()
                  );
                  usernamePasswordAuthenticationToken.setDetails(
                          new WebAuthenticationDetailsSource().buildDetails(httpServletRequest)
                  );
                  SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
              }
          }
  
          filterChain.doFilter(httpServletRequest, httpServletResponse);
      }
  }
  ```

- SecurityConfig中去除Session，添加jwtRequestFilter拦截

  ```java
  @Autowired
  private JwtRequestFilter jwtRequestFilter;
  
  @Override
  protected void configure(HttpSecurity http) throws Exception {
      http
          .csrf().disable()
          .authorizeRequests().antMatchers("/authenticate").permitAll()
          .anyRequest().authenticated()
          .and().sessionManagement()
          .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
  
      http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
  }
  ```

  


**[代码地址](!https://github.com/ywkpl/jwttoken)**

**[参考视频](!https://www.youtube.com/watch?v=X80nJ5T7YpE)**