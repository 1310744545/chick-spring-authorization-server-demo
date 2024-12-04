package chick.authorization.token;

import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * @Author xkx
 * @Description 自定义token生成器
 * @Date 2024/12/3 22:33
 * @Param
 * @return
 **/
public class UUIDOAuth2TokenGenerator implements OAuth2TokenGenerator<OAuth2AccessToken> {

    private final StringKeyGenerator accessTokenGenerator = new UUIDKeyGenerator();

    private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;

    @Override
    public OAuth2AccessToken generate(OAuth2TokenContext context) {
        // @formatter:off
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) ||
                !OAuth2TokenFormat.REFERENCE.equals(context.getRegisteredClient().getTokenSettings().getAccessTokenFormat())) {
            return null;
        }
        // @formatter:on

        String issuer = null;
        if (context.getAuthorizationServerContext() != null) {
            issuer = context.getAuthorizationServerContext().getIssuer();
        }
        RegisteredClient registeredClient = context.getRegisteredClient();

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive());

        // @formatter:off
        OAuth2TokenClaimsSet.Builder claimsBuilder = OAuth2TokenClaimsSet.builder();
        if (StringUtils.hasText(issuer)) {
            claimsBuilder.issuer(issuer);
        }
        claimsBuilder
                .subject(context.getPrincipal().getName())
                .audience(Collections.singletonList(registeredClient.getClientId()))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .notBefore(issuedAt)
                .id(UUID.randomUUID().toString());
        if (!CollectionUtils.isEmpty(context.getAuthorizedScopes())) {
            claimsBuilder.claim(OAuth2ParameterNames.SCOPE, context.getAuthorizedScopes());
        }
        OAuth2TokenClaimsSet accessTokenClaimsSet = claimsBuilder.build();

        return new OAuth2AccessTokenClaims(OAuth2AccessToken.TokenType.BEARER,
                this.accessTokenGenerator.generateKey(), accessTokenClaimsSet.getIssuedAt(), accessTokenClaimsSet.getExpiresAt(),
                context.getAuthorizedScopes(), accessTokenClaimsSet.getClaims());
    }

    private static final class OAuth2AccessTokenClaims extends OAuth2AccessToken implements ClaimAccessor {
        private final Map<String, Object> claims;

        private OAuth2AccessTokenClaims(TokenType tokenType, String tokenValue,
                                        Instant issuedAt, Instant expiresAt, Set<String> scopes, Map<String, Object> claims) {
            super(tokenType, tokenValue, issuedAt, expiresAt, scopes);
            this.claims = claims;
        }

        @Override
        public Map<String, Object> getClaims() {
            return this.claims;
        }

    }

    public OAuth2TokenCustomizer<JwtEncodingContext> getJwtCustomizer() {
        return jwtCustomizer;
    }

    public void setJwtCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        this.jwtCustomizer = jwtCustomizer;
    }
}
