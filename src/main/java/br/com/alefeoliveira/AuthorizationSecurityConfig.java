package br.com.alefeoliveira;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;


@Configuration
@EnableWebSecurity
public class AuthorizationSecurityConfig {
	
	@Autowired
	private RedisConnectionFactory redisConnectionFactory;
	
	  @Bean
	    @Order(1)
	    public SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {
	        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
	        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults())
	        .authorizationEndpoint(authorizationEndpoint ->
			authorizationEndpoint.consentPage("/oauth2/v1/authorize"));
	        return http.build();
	    }
	  
	    @SuppressWarnings("removal")
		@Bean
	    @Order(2)
	    public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
	        http.csrf(csrf -> csrf.disable()).anonymous(anom -> anom.disable())
	        .authorizeHttpRequests(oauth -> oauth.anyRequest().permitAll())
	        .httpBasic(Customizer.withDefaults())
	        .securityContext((securityContext) -> securityContext.securityContextRepository(securityContextRepository())) // Add Security Context Holder Repository
            .authenticationProvider(authenticationProvider());
	       
	        return http.build();
	    }
	    

	    @Bean
	    public UserDetailsService userDetailsService() {
	        UserDetails user1 = User.withUsername("alefe").password(passwordEncoder().encode("123")).authorities("read").build();
	        return new InMemoryUserDetailsManager(user1);
	    }

	    @Bean
	    public PasswordEncoder passwordEncoder() {
	        return new BCryptPasswordEncoder();
	    }

	    @Bean
	    public RegisteredClientRepository registeredClientRepository() {
	        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
	                .clientId("client")
	                .clientSecret(passwordEncoder().encode("secret"))
	                .scope("read")
	                .scope(OidcScopes.OPENID)
	                .scope(OidcScopes.PROFILE)
	                .scope("offline_access")
	                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/myoauth2")
	                .redirectUri("https://localhost:9000/callback")
	                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
	                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
	                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
	                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
	                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
	                .tokenSettings(
	                        TokenSettings.builder()
	                            .accessTokenFormat(OAuth2TokenFormat.REFERENCE) 
	                            .accessTokenTimeToLive(Duration.ofSeconds(30))
	                            .build())
	                .build();
	        return  new InMemoryRegisteredClientRepository(registeredClient);
	    }
	    
	    @Bean
	    public AuthorizationServerSettings authorizationServerSettings() {
	        return  AuthorizationServerSettings.builder()
	        		.build();
	    }
	    
	    @Bean
	    public AuthenticationProvider authenticationProvider(){
	        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
	        authenticationProvider.setUserDetailsService(userDetailsService());
	        authenticationProvider.setPasswordEncoder(passwordEncoder());
	        return authenticationProvider;
	    }
	    
	    @Bean
	    public SecurityContextRepository securityContextRepository(){
	        return new NullSecurityContextRepository(); // I use Null Repository since I don't need it for anything except store information in UserDetails
	    }

	    @Bean
	    public TokenSettings tokenSettings() {
	        return TokenSettings.builder().build();
	    }

	    @Bean
	    public ClientSettings clientSettings() {
	        return ClientSettings.builder()
	                .requireAuthorizationConsent(false)
	                .requireProofKey(false).build();
	    }

	    @Bean
	    public JWKSource<SecurityContext> jwkSource() {
	        RSAKey rsaKey = generateRsa();
	        JWKSet jwkSet = new JWKSet(rsaKey);
	        return ((jwkSelector, securityContext) -> jwkSelector.select(jwkSet));
	    }

	    public static RSAKey generateRsa() {
	        KeyPair keyPair = generateRsaKey();
	        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
	        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
	        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();

	    }

	    static KeyPair generateRsaKey() {
	        KeyPair keyPair = null;
	        try {
	            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	            keyPairGenerator.initialize(2048);
	            keyPair = keyPairGenerator.generateKeyPair();
	        }
	        catch (NoSuchAlgorithmException e) {
	            throw new IllegalArgumentException(e);
	        }
	        return keyPair;
	    }
}
