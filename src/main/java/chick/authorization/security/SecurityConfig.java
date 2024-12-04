package chick.authorization.security;

import chick.authorization.granter.CustomAuthorizationGrantType;
import chick.authorization.granter.password.OAuth2PasswordAuthenticationConverter;
import chick.authorization.granter.password.OAuth2PasswordAuthenticationProvider;
import chick.authorization.token.ChickReferenceTokenEnhancer;
import chick.authorization.token.ChickSelfContainedTokenEnhancer;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // 透明token扩展
    private final ChickSelfContainedTokenEnhancer chickSelfContainedTokenEnhancer;
    // 非透明token扩展
    private final ChickReferenceTokenEnhancer chickReferenceTokenEnhancer;
    // 数据库链接
    private final JdbcTemplate jdbcTemplate;
    // 密码编码器
    private final PasswordEncoder passwordEncoder;
    // jwt编码器
    private final JwtEncoder jwtEncoder;
    // 客户端管理
    private final RegisteredClientRepository registeredClientRepository;
    // 用户检索
    private final UserDetailsService userDetailsService;
    // 扩展Provider
    private final OAuth2PasswordAuthenticationProvider oAuth2PasswordAuthenticationProvider;
    // 扩展Converter
    private final OAuth2PasswordAuthenticationConverter oAuth2PasswordAuthenticationConverter;

    public SecurityConfig(ChickSelfContainedTokenEnhancer chickSelfContainedTokenEnhancer,
                          ChickReferenceTokenEnhancer chickReferenceTokenEnhancer,
                          JdbcTemplate jdbcTemplate,
                          @Lazy PasswordEncoder passwordEncoder,
                          @Lazy JwtEncoder jwtEncoder,
                          @Lazy RegisteredClientRepository registeredClientRepository,
                          @Lazy UserDetailsService userDetailsService,
                          @Lazy OAuth2PasswordAuthenticationProvider oAuth2PasswordAuthenticationProvider,
                          @Lazy OAuth2PasswordAuthenticationConverter oAuth2PasswordAuthenticationConverter) {
        this.chickSelfContainedTokenEnhancer = chickSelfContainedTokenEnhancer;
        this.chickReferenceTokenEnhancer = chickReferenceTokenEnhancer;
        this.jdbcTemplate = jdbcTemplate;
        this.passwordEncoder = passwordEncoder;
        this.jwtEncoder = jwtEncoder;
        this.registeredClientRepository = registeredClientRepository;
        this.userDetailsService = userDetailsService;
        this.oAuth2PasswordAuthenticationProvider = oAuth2PasswordAuthenticationProvider;
        this.oAuth2PasswordAuthenticationConverter = oAuth2PasswordAuthenticationConverter;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, Customizer.withDefaults())
                .authorizeHttpRequests((authorize) ->
                        authorize.anyRequest().authenticated()
                )
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                ).oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()))
                .with(authorizationServerConfigurer, (authorizationServer) -> authorizationServer
                        .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                                .accessTokenRequestConverter(oAuth2PasswordAuthenticationConverter)
                                .authenticationProvider(oAuth2PasswordAuthenticationProvider)
                        )
                );
        http
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        //JdbcDaoImpl jdbcDao = new JdbcDaoImpl();
        //jdbcDao.setJdbcTemplate(jdbcTemplate);
        UserDetails userDetails = User.withUsername("admin")
                .password(passwordEncoder().encode("123123"))
                .roles("admin")
                .build();
        return new InMemoryUserDetailsManager(userDetails);
        //return jdbcDao;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);

        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofHours(1)) // 设置访问令牌有效期为1小时
                .refreshTokenTimeToLive(Duration.ofDays(30)) // 设置刷新令牌有效期为30天
                //.accessTokenFormat(OAuth2TokenFormat.REFERENCE) // 这个设置是开启不透明token
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED) // 使用透明token(默认)
                .build();
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("chick")
                .clientSecret(passwordEncoder().encode("123456"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(CustomAuthorizationGrantType.PASSWORD)
                .redirectUri("https://www.baidu.com")
                .postLogoutRedirectUri("http://127.0.0.1:8000/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .tokenSettings(tokenSettings)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        return new InMemoryRegisteredClientRepository(oidcClient);
        //jdbcRegisteredClientRepository.save(oidcClient);//第一次启动可以打开这个 将客户端保存到数据库
        //return jdbcRegisteredClientRepository;
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService() {
        return new InMemoryOAuth2AuthorizationService(); //使用内存
        //return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository); // 使用数据库
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * token生成器。配置要使用的token生成器
     **/
    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator() {
        // 当客户端的tokenSetting的OAuth2TokenFormat设置为OAuth2TokenFormat.SELF_CONTAINED时 使用下面的
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);// jwtToken生成器（当客户端的token格式为self-contained时使用）
        jwtGenerator.setJwtCustomizer(chickSelfContainedTokenEnhancer);// 设置jwt-token自定义扩展

        // 当客户端的tokenSetting的OAuth2TokenFormat设置为OAuth2TokenFormat.REFERENCE 使用下面的
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();// 不透明的token生成器
        accessTokenGenerator.setAccessTokenCustomizer(chickReferenceTokenEnhancer);// 设置id-token自定义扩展

        // refreshToken生成器
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();// refreshToken生成器
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }
}