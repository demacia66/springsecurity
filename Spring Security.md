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

### 两个重要的接口

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
