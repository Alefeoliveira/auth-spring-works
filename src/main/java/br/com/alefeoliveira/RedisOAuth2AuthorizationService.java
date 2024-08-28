package br.com.alefeoliveira;

import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final String AUTHORIZATION_KEY = "oauth2:authorization:";
    private final RedisTemplate<String, OAuth2Authorization> redisTemplate;

    public RedisOAuth2AuthorizationService(RedisTemplate<String, OAuth2Authorization> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        String key = AUTHORIZATION_KEY + authorization.getId();
        redisTemplate.opsForValue().set(key, authorization);
        redisTemplate.expire(key, 10, TimeUnit.MINUTES);  // Define um tempo de expiração
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        String key = AUTHORIZATION_KEY + authorization.getId();
        redisTemplate.delete(key);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        String key = AUTHORIZATION_KEY + id;
        return redisTemplate.opsForValue().get(key);
    }

	@Override
	public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
		// TODO Auto-generated method stub
		return null;
	}
}