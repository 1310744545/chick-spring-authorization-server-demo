package chick.authorization.granter;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

/*
    扩展GrantType类型
 */
public record CustomAuthorizationGrantType(String value) {

    // 账号密码模式
    public static final AuthorizationGrantType PASSWORD = new AuthorizationGrantType("password");
}
