# Spring Security

1. FilterSecurityInterceptor:是一个方法级的权限过滤器，基本位于过滤器链的最底部

2. ExceptionTraslationFilter：是一个异常过滤器，用来处理认证授权中抛出的异常

3. UsernamePasswordAuthenticationFilter：检验表单中用户名和密码

   ```java
   @Override
   public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
         throws AuthenticationException {
       //先判断是否是post请求
      if (this.postOnly && !request.getMethod().equals("POST")) {
         throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
      }
      //获取用户名
      String username = obtainUsername(request);
      username = (username != null) ? username : "";
      username = username.trim();
       //获取密码
      String password = obtainPassword(request);
      password = (password != null) ? password : "";
      UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
      // Allow subclasses to set the "details" property
      setDetails(request, authRequest);
      return this.getAuthenticationManager().authenticate(authRequest);
   }
   ```

过滤器如何进行加载？

1. 使用SpringSecurity配置过滤器

   DelegatingFilterProxy

   ```java
   @Override
   public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
         throws ServletException, IOException {
   
      // Lazily initialize the delegate if necessary.
      Filter delegateToUse = this.delegate;
      if (delegateToUse == null) {
         synchronized (this.delegateMonitor) {
            delegateToUse = this.delegate;
            if (delegateToUse == null) {
               WebApplicationContext wac = findWebApplicationContext();
               if (wac == null) {
                  throw new IllegalStateException("No WebApplicationContext found: " +
                        "no ContextLoaderListener or DispatcherServlet registered?");
               }
                //初始化
               delegateToUse = initDelegate(wac);
            }
            this.delegate = delegateToUse;
         }
      }
   ```

   ```java
   protected Filter initDelegate(WebApplicationContext wac) throws ServletException {
       //filterChainProxy
      String targetBeanName = getTargetBeanName();
      Assert.state(targetBeanName != null, "No target bean name set");
      Filter delegate = wac.getBean(targetBeanName, Filter.class);
      if (isTargetFilterLifecycle()) {
         delegate.init(getFilterConfig());
      }
      return delegate;
   }
   ```

   filterChainProxy中的方法

   ```java
   private void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
   			throws IOException, ServletException {
   		FirewalledRequest firewallRequest = this.firewall.getFirewalledRequest((HttpServletRequest) request);
   		HttpServletResponse firewallResponse = this.firewall.getFirewalledResponse((HttpServletResponse) response);
       //得到所有的过滤器
   		List<Filter> filters = getFilters(firewallRequest);
   		if (filters == null || filters.size() == 0) {
   			if (logger.isTraceEnabled()) {
   				logger.trace(LogMessage.of(() -> "No security for " + requestLine(firewallRequest)));
   			}
   			firewallRequest.reset();
   			chain.doFilter(firewallRequest, firewallResponse);
   			return;
   		}
   		if (logger.isDebugEnabled()) {
   			logger.debug(LogMessage.of(() -> "Securing " + requestLine(firewallRequest)));
   		}
   		VirtualFilterChain virtualFilterChain = new VirtualFilterChain(firewallRequest, chain, filters);
   		virtualFilterChain.doFilter(firewallRequest, firewallResponse);
   	}
   
   	private List<Filter> getFilters(HttpServletRequest request) {
   		int count = 0;
   		for (SecurityFilterChain chain : this.filterChains) {
   			if (logger.isTraceEnabled()) {
   				logger.trace(LogMessage.format("Trying to match request against %s (%d/%d)", chain, ++count,
   						this.filterChains.size()));
   			}
   			if (chain.matches(request)) {
   				return chain.getFilters();
   			}
   		}
   		return null;
   	}
   //SecurityFilterChain类
   public interface SecurityFilterChain {
   
   	boolean matches(HttpServletRequest request);
   
   	List<Filter> getFilters();
   
   }
   ```

## 两个重要的接口

1. UserDetailsService 接口讲解

   当什么也没有配置的情况下，账号和密码都是由Spring Security定义生成的。而在设计项目中账号和密码都是从数据库中查询出来的。所以我们要通过自定义逻辑控制认证逻辑。

   如果需要自定义逻辑时，只需要实现UserDetailsService接口来进行数据库查询逻辑写入即可，即这个接口写查询数据库用户名和密码的过程。

   ```java
   public interface UserDetailsService {
      UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
   }
   ```

   步骤：

   1. 创建类继承UsernamePasswordAuthenticationFilter,重写三个方法attemptAuthentication、successfulAuthentication、unsuccessfulAuthentication
   2. 创建类实现UserDetailsService，编写查询数据过程，返回User对象，这个User对象是安全框架提供对象

2. PasswordEncoder接口：进行密码加密，用于返回user对象里面密码加密



## web权限方案

### 设置用户名和密码

1. 通过配置文件application.properties

   ```properties
   server.port=8111
   spring.security.user.name=at
   spring.security.user.password=at
   ```

2. 通过配置类

   ````java
   
   @Configuration
   public class SecurityConfig extends WebSecurityConfigurerAdapter {
   
       //可以设置用户名和密码
       @Override
       protected void configure(AuthenticationManagerBuilder auth) throws Exception {
           //用于加密
           BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
           //进行加密
           String password = passwordEncoder.encode("123");
           //用户名，密码，角色
           auth.inMemoryAuthentication().withUser("lucy").password(password).roles("admin");
       }
   
       @Bean
       PasswordEncoder password(){
           return new BCryptPasswordEncoder();
       }
   }
   ````

   

3. 自定义编写实现类

   1. 创建配置类，设置使用哪个userDetailsService实现类

      ```java
      @Configuration
      public class SecurityConfigTest extends WebSecurityConfigurerAdapter {
          
          @Autowired
          private UserDetailsService userDetailsService;
          
          
          @Override
          protected void configure(AuthenticationManagerBuilder auth) throws Exception {
              auth.userDetailsService(userDetailsService).passwordEncoder(password());
          }
          
          @Bean
          PasswordEncoder password(){
              return new BCryptPasswordEncoder();
          }
      }
      ```

   2. 编写实现类，返回User对象，User对象有用户名密码和操作权限

      ```java
      @Configuration
      public class SecurityConfigTest extends WebSecurityConfigurerAdapter {
      
          @Autowired
          private UserDetailsService userDetailsService;
      
      
          @Override
          protected void configure(AuthenticationManagerBuilder auth) throws Exception {
              auth.userDetailsService(userDetailsService).passwordEncoder(password());
          }
      
          @Bean
          PasswordEncoder password(){
              return new BCryptPasswordEncoder();
          }
      }
      ```

      ```java
      @Service("userDetailsService")//名字要一样，否则注入不进去
      public class MyUserDetailsService implements UserDetailsService {
          @Override
          public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
              List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("role");
              //权限不能写空
              return new User("mary",new BCryptPasswordEncoder().encode("123"),auths);
          }
      }
      ```

### 实现数据库认证来完成数据库登录

准备sql，整合MyBatisPlus完成数据库操作

1. 引入相关依赖

   ```xml
   <!--        mybatis-plus-->
           <dependency>
               <groupId>com.baomidou</groupId>
               <artifactId>mybatis-plus-boot-starter</artifactId>
               <version>3.0.5</version>
           </dependency>
   
   <!--        mysql-->
           <dependency>
               <groupId>mysql</groupId>
               <artifactId>mysql-connector-java</artifactId>
           </dependency>
   
           <!--lombok用来简化实体类-->
           <dependency>
               <groupId>org.projectlombok</groupId>
               <artifactId>lombok</artifactId>
           </dependency>
   ```

2. 创建数据库和数据表

3. 创建users表对应的实体类

   ```java
   @Data//生成对应的get set toString
   public class Users {
   
       private Integer id;
       private String username;
       private String password;
   }
   ```

4. 整合mp，创建接口，继承mp的接口

   ```java
   @Repository//不加会报错
   public interface UserMapper extends BaseMapper<Users> {
   }
   ```

5. 在MyUserDetailsService调用mapper里面的方法查询数据库

   ```java
   @Service("userDetailsService")
   public class MyUserDetailsService implements UserDetailsService {
       @Autowired
       private UserMapper userMapper;
   
       @Override
       public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
   
           //调用userMapper方法调用数据库,根据用户名查询数据库
           //查询构造器
           QueryWrapper<Users> wrapper = new QueryWrapper<>();
           // where username=?
           wrapper.eq("username",username);
   
           Users users = userMapper.selectOne(wrapper);
           //判断
           if (users == null){
               //数据库中没有用户名，认证失败
               throw new UsernameNotFoundException("用户名不存在！");
           }
   
           List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("role");
           //从数据库中返回Users对象，得到用户名密码，返回
           return new User(users.getUsername(), new BCryptPasswordEncoder().encode(users.getUsername()), auths);
   
   //        List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("role");
   //        //权限不能写空
   //        return new User("mary", new BCryptPasswordEncoder().encode("123"), auths);
       }
   }
   ```

6. 在启动类添加注解 MapperScan

   ```java
   @SpringBootApplication
   @MapperScan("com.atguigu.securitydemo1.mapper")
   public class Securitydemo1Application {
   
       public static void main(String[] args) {
           SpringApplication.run(Securitydemo1Application.class, args);
       }
   
   }
   ```

7. 数据库配置

   ```properties
   spring.datasource.url=jdbc:mysql://localhost:3306/security?serverTimezone=UTC&characterEncoding=utf8&characterSetResults=utf8&autoReconnect=true&failOverReadOnly=false&useSSL=true
   spring.datasource.username=root
   spring.datasource.password=Wico@60213030
   spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
   ```



### 自定义设置登陆页面不需要认证可以访问

1. 在配置类实现相关的配置,index需要登陆，hello不需要

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.formLogin() //自定义自己编写的登陆页面
    .loginPage("/login.html")//登陆页面设置
    .loginProcessingUrl("/user/login")//登陆访问路径
    .defaultSuccessUrl("/test/index").permitAll()//登陆成功跳转
    .and().authorizeRequests()//那些需要认证
    .antMatchers("/","/test/hello","/user/login").permitAll()//那些路径可以直接访问，不需要认证
    .anyRequest().authenticated()//所有请求都可以访问
    .and().csrf().disable();//关闭csrf防护
}
```

### 基于角色或权限进行访问控制

1. hasAuthority方法

   如果当前的主体具有指定的权限,则返回true,否则返回false,一个路径只能一个权限访问

   1. 在设置类设置当前访问地址有哪些权限

        //当前登陆用户，只有具有admins权限才可以访问这个路径

      ```java
      @Override
          protected void configure(HttpSecurity http) throws Exception {
              http.formLogin() //自定义自己编写的登陆页面
              .loginPage("/login.html")//登陆页面设置
              .loginProcessingUrl("/user/login")//登陆访问路径
              .defaultSuccessUrl("/test/index").permitAll()//登陆成功跳转
              .and().authorizeRequests()//那些需要认证
      //        .antMatchers("/","/test/hello","/user/login").permitAll()//那些路径可以直接访问，不需要认证
                
               //当前登陆用户，只有具有admins权限才可以访问这个路径
              .antMatchers("/test/index").hasAuthority("admins")
              .anyRequest().authenticated()//所有请求都可以访问
              .and().csrf().disable();//关闭csrf防护
          }
      ```

   2. 在UserDeatilsService,把返回User对象设置权限

      ```java
      //查到的用户给予admins权限
      List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("admins");
      ```

       

2. hasAnyAuthority方法

   ```java
   //admins和manager都可以访问
   .antMatchers("/test/index").hasAnyAuthority("admins,manager")
   ```

3. hasRole方法

   如果用户具备给定角色就允许访问,否则出现403

   如果当前主体具有指定的角色,则返回true

   底层源码

   ```java
   private static String hasRole(String role) {
      Assert.notNull(role, "role cannot be null");
      Assert.isTrue(!role.startsWith("ROLE_"),
            () -> "role should not start with 'ROLE_' since it is automatically inserted. Got '" + role + "'");
      return "hasRole('ROLE_" + role + "')";
   }
   ```

   ```java
   //查到的用户给予admins权限和角色
   List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("admins,ROLE_sale");
   ```

   ```java
   //3 hasRole方法
   //ROLE_sale
   .antMatchers("/test/index").hasRole("sale")
   ```

4. hasAnyRole

   用户具有任何一个都可以访问

### 自定义403页面

1. 在配置类里配置

   ```java
   @Override
   protected void configure(HttpSecurity http) throws Exception {
   
       //在配置类配置没有权限访问跳转自定义页面
       http.exceptionHandling().accessDeniedPage("/unauth.html");
   ```

### 注解使用

1. @Secured

   判断是否具有角色，另外需要注意的是这里匹配的字符串需要添加前缀"ROLE"

   用户具有某个角色，可以访问方法

   1. 先开启注解，可以在配置类或者启动类上

      ```java
      @SpringBootApplication
      @MapperScan("com.atguigu.securitydemo1.mapper")
      //开启spring security注解
      @EnableGlobalMethodSecurity(securedEnabled = true)
      public class Securitydemo1Application {
      
          public static void main(String[] args) {
              SpringApplication.run(Securitydemo1Application.class, args);
          }
      
      }
      ```

   2. 在controller的方法上面使用注解，设置角色

      ```java
      @GetMapping("update")
      @Secured({"ROLE_sale","ROLE_manager"})
      public String update(){
          return "hello update";
      }
      ```

   3. userDetailsService设置用户

      ```java
      List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("admins,ROLE_sale");
      ```

2. @PreAuthorize:注解适合进入方法前的权限验证，@PreAuthorize可以将登录用户的roles/permissions参数传到方法中

   1. 在启动类上开启注解

      ```java
      @EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)
      ```

   2. 在controller的方法上添加注解

      ```java
      @GetMapping("update")
      //    @Secured({"ROLE_sale","ROLE_manager"})
          @PreAuthorize("hasAnyAuthority('admins')")
          public String update(){
              return "hello update";
          }
      ```

3. @PostAuthorize:注解使用的不多，在方法执行后再进行权限认证，适合验证带有返回值的权限

   1. 先开启注解

      ```java
      @EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)
      ```

   2. 方法上添加注解,没有权限先打印再跳转403

      ```java
      @GetMapping("update")
      //    @Secured({"ROLE_sale","ROLE_manager"})
      //    @PreAuthorize("hasAnyAuthority('admins')")
          @PostAuthorize("hasAnyAuthority('admins')")
          public String update(){
              System.out.println("hello");
              return "hello update";
          }
      ```

4. @PostFilter

   权限认证后对数据进行过滤，留下的用户名为admin1的数据，对返回做过滤,不用启动注解即可

   表达式中的filterObject引用的是方法返回值List中的某一个元素

   ````java
   @RequestMapping("getAll")
   @PreAuthorize("hasRole('ROLE_管理员')")
   @PostFilter("filterObject.username == 'admin1'")
   @ResponseBody
   public List<UserInfo> getAllUser(){
       ArrayList<UserInfo> list = new ArrayList<>();
       list.add(new UserInfo(1l,"admin1","6666"));
       list.add(new UserInfo(2l,"admin2","888"));
       return list;
   }
   ````

5. @PreFilter 进入控制器之前对数据进行过滤，对参数过滤

   ````java
   @RequestMapping("getTestPreFilter")
   @PreAuthorize("hasRole('ROLE_管理员')")
   @PreFilter(value = "filterObject.id%2==0")
   @ResponseBody
   public List<UserInfo> getTestFilter(@RequestBody List<UserInfo> list){
       list.fotEach(t-> {
           System.out.println(t.getId() + "\t" + t.getUsername());
       });
       return list;
   }
   ````

### 用户注销

1. 在配置类添加退出的配置

   ```java
   //退出
   http.logout().logoutUrl("/logout").logoutSuccessUrl("/test/hello").permitAll();
   ```

### 记住我

1. cookie

2. 安全机制实现自动登录

   1. 实现原理

      浏览器存：cookie、加密串
      数据库：加密串、用户信息字符串

   2. 再次进行访问

      获取cookie信息，拿着cookie信息到数据库中进行比对，如果查询到对应信息，认证成功，可以登录

   3. 具体实现

      - 创建数据库表,建表语句可见JdbcTokenRepositoryImpl类

        ````sql
        create table persistent_logins (username varchar(64) not null, series varchar(64) primary key,token varchar(64) not null, last_used timestamp not null DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)ENGINE=InnoDB DEFAULT CHARSET=utf8;
        ````

      - 配置类，注入数据源，配置操作数据库对象

        ```java
         //注入数据源
            @Autowired
            private DataSource dataSource;
            //配置对象
            @Bean
            public PersistentTokenRepository persistentTokenRepository(){
                JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
                jdbcTokenRepository.setDataSource(dataSource);
                //启动时创建表
        //        jdbcTokenRepository.setCreateTableOnStartup(true);
                return jdbcTokenRepository;
            }
        ```

      - 配置类中配置自动登录

        ````java
         http.formLogin() //自定义自己编写的登陆页面
                        .loginPage("/login.html")//登陆页面设置
                        .loginProcessingUrl("/user/login")//登陆访问路径
                        .defaultSuccessUrl("/success.html").permitAll()//登陆成功跳转
                        .and().authorizeRequests()//那些需要认证
        //        .antMatchers("/","/test/hello","/user/login").permitAll()//那些路径可以直接访问，不需要认证
                        //当前登陆用户，只有具有admins权限才可以访问这个路径
        //        .antMatchers("/test/index").hasAuthority("admins")
                        //admins和manager都可以访问
        //                .antMatchers("/test/index").hasAnyAuthority("admins,manager")
        
                        //3 hasRole方法
                        //ROLE_sale
                        .antMatchers("/test/index").hasRole("sale")
                        .anyRequest().authenticated()//所有请求都可以访问
                        .and().rememberMe().tokenRepository(persistentTokenRepository())
                        //60秒可用
                        .tokenValiditySeconds(60)
                        //设置userDetail，底层用它来使用数据库
                        .userDetailsService(userDetailsService)
                        .and().csrf().disable();//关闭csrf防护
        ````

      - 在登录页面添加复选框,name一定是remember-me

        ```html
        <input type="checkbox" name="remember-me">自动登录
        ```

### CSRF

跨站请求伪造，是一种挟制用户在当前已登录的Web应用程序上执行非本意的操作的攻击方法。跟跨网站脚本相比，XSS利用的是用户对指定网站的信任，CSRF利用的是网站对用户网页浏览器的信任，网站可能得到用户在其他网站的cookie信息，csrf默认是开启的，会针对PATCH，POST，PUT，DELETE方法进行保护