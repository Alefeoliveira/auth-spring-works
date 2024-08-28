package br.com.alefeoliveira;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;

public class RedisOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

    private static final String CONSENT_KEY = "oauth2:authorization:consent:";
    private final RedisTemplate<String, OAuth2AuthorizationConsent> redisTemplate;

    public RedisOAuth2AuthorizationConsentService(RedisTemplate<String, OAuth2AuthorizationConsent> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void save(OAuth2AuthorizationConsent consent) {
        String key = CONSENT_KEY + consent.getRegisteredClientId() + ":" + consent.getPrincipalName();
        redisTemplate.opsForValue().set(key, consent);
    }

    @Override
    public void remove(OAuth2AuthorizationConsent consent) {
        String key = CONSENT_KEY + consent.getRegisteredClientId() + ":" + consent.getPrincipalName();
        redisTemplate.delete(key);
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        String key = CONSENT_KEY + registeredClientId + ":" + principalName;
        return redisTemplate.opsForValue().get(key);
    }
}
