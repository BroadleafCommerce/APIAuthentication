# Module Installation

Steps to enable this module in your custom Broadleaf Commerce project

## Steps

1. Add this dependency to your `api` project

```xml
<dependency>
    <groupId>org.broadleafcommerce</groupId>
    <artifactId>broadleaf-api-authentication</artifactId>
</dependency>
```

> Note: You should add this to a project already utilized `broadleaf-rest-api`

2. Modify your `WebSecurityConfigurerAdapter` implementation (`ApiSecurityConfig`) to include the following configuration beans:

  
```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class ApiSecurityConfig extends WebSecurityConfigurerAdapter {

    protected final AccessTokenAuthenticationProvider accessTokenAuthenticationProvider;
    protected final RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider;
    protected final PasswordEncoder passwordEncoder;
    protected final UserDetailsService userDetailsService;
    protected final ApiAuthenticationRequestFactory apiAuthenticationRequestFactory;

    @Autowired
    public ApiSecurityConfig(AccessTokenAuthenticationProvider accessTokenAuthenticationProvider,
                             RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider,
                             PasswordEncoder passwordEncoder, UserDetailsService userDetailsService,
                             ApiAuthenticationRequestFactory apiAuthenticationRequestFactory) {
        this.accessTokenAuthenticationProvider = accessTokenAuthenticationProvider;
        this.refreshTokenAuthenticationProvider = refreshTokenAuthenticationProvider;
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
        this.apiAuthenticationRequestFactory = apiAuthenticationRequestFactory;
    }

    @Bean(name="blAuthenticationManager")
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public AuthenticationProvider blAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(blAuthenticationProvider()) // <---- add normal dao auth provider for login/register
            .authenticationProvider(accessTokenAuthenticationProvider) // <---- add access token auth provider
            .authenticationProvider(refreshTokenAuthenticationProvider); // <---- add refresh token auth provider
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/api/**/login").permitAll() // <--- permit access to login filter
                .antMatchers(HttpMethod.POST, "/api/**/register").permitAll() // <-- permit access to register filter
                
                ...
                
                // add access token filter
                .addFilterBefore(apiAuthenticationRequestFactory.buildAccessTokenAuthenticationFilter("/**", authenticationManagerBean()), UsernamePasswordAuthenticationFilter.class)
                
                // add refresh token filter
                .addFilterBefore(apiAuthenticationRequestFactory.buildRefreshTokenAuthenticationFilter("/api/**/refresh-token", authenticationManagerBean()), AccessTokenAuthenticationFilter.class)
                
                // add login filter
                .addFilterBefore(apiAuthenticationRequestFactory.buildLoginFilter("/api/**/login", authenticationManagerBean()), AccessTokenAuthenticationFilter.class)
                
                // add register filter
                .addFilterBefore(apiAuthenticationRequestFactory.buildRegisterFilter("/api/**/register", authenticationManagerBean()), AccessTokenAuthenticationFilter.class);
    }
    
    ...
    
}
```

3. Optionally, modify your implementation of `CartEndpoint` to do the following for `createNewCartForCustomer` so "anonymous" users can retrieve the same cart.

```java
@RequestMapping(value = "", method = RequestMethod.POST)
public OrderWrapper createNewCartForCustomer(HttpServletRequest request, HttpServletResponse response) {
    OrderWrapper resultWrapper = super.createNewCartForCustomer(request);

    // if this is not a registered customer, send an anonymous customer token that the user can use for future requests as an anonymous customer
    if (!resultWrapper.getCustomer().isRegistered()) {
        String customerToken = authenticationTokenService.generateCustomerToken(resultWrapper.getCustomer().getId());
        response.addHeader(getCustomerTokenHeader(), customerToken);
    }
    return resultWrapper;
}

protected String getCustomerTokenHeader() {
    return environment.getProperty("blc.auth.jwt.customer.header");
}
```

## How It Works

#### Anonymous Customers

When your client application requires a new cart, it does a POST to `/cart` and the response includes the cart in the body and a customer token in the `X-Customer-Token` header. This token can then be passed in subsequent requests as the `X-Customer-Token` header in order to establish the Customer state for the request in `ApiCustomerStateFilter`.

#### Registered Customers

When your client application processes login or register, the authentication filters, upon success, will return an access token in the `Authorization` header and a refresh token in an http-only secure cookie named `blRefreshToken`. Future requests from the client may pass the access token in the `Authorization` header to authenticate these requests. Upon expiration of the access token, which defaults to every 15 minutes, the client must use the refresh token to get a new access token. This can be done by making a request to `/refresh-token`. The refresh token filter will look for the http-only refresh token cookie, and if it exists and is valid, it will successfully authenticate and return a new access token in the `Authorization` header. The client should then use this new access token in future requests. 

#### JWT

The default implementations `JWTAuthenticationTokenServiceImpl` and `JWTCustomerStateServiceImpl` use Json Web Tokens (JWT) for generating and parsing the access and refresh tokens. If you do not want to use JWT for your implementation you can create your own implementations of `AuthenticationTokenService` and `CustomerStateService` and set the system property `blc.auth.jwt.enabled` to `false`.

