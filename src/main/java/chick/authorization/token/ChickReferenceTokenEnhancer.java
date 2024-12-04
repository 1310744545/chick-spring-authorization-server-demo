package chick.authorization.token;

import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Service;

/**
* @Author xkx
* @Description 不透明token扩展
* @Date 2024/11/28 21:33
* @Param
* @return
**/
@Service
public class ChickReferenceTokenEnhancer implements OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {
    @Override
    public void customize(OAuth2TokenClaimsContext context) {
        context.getClaims().claims(claims -> {
            claims.put("custom1", "1");
            claims.put("custom2", "2");
        });
    }
}
