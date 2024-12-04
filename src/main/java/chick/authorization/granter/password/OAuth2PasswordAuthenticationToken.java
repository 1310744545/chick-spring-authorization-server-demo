package chick.authorization.granter.password;

import chick.authorization.granter.CustomAuthorizationGrantType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;

/**
* @Author xkx
* @Description 用户名密码令牌扩展
* @Date 2024/12/1 20:16
* @Param
* @return
**/
public class OAuth2PasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    private final String username;
    private final String password;

    public OAuth2PasswordAuthenticationToken(String username, String password, Authentication clientPrincipal, Map<String, Object> additionalParameters) {
        super(CustomAuthorizationGrantType.PASSWORD, clientPrincipal, additionalParameters);
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
