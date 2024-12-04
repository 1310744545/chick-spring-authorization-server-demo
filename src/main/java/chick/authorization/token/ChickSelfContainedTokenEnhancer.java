package chick.authorization.token;

import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Service;

/**
 * @Author xkx
 * @Description 透明token扩展
 * @Date 2024/11/28 21:33
 * @Param
 * @return
 **/
@Service
public class ChickSelfContainedTokenEnhancer implements OAuth2TokenCustomizer<JwtEncodingContext> {
    @Override
    public void customize(JwtEncodingContext context) {
        context.getClaims().claims(claims -> {
            claims.put("custom1", "1");
            claims.put("custom2", "2");
        });
    }
}
