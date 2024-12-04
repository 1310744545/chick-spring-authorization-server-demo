package chick.authorization.token;

import org.springframework.security.crypto.keygen.StringKeyGenerator;

import java.util.UUID;

/*
   uuid生成
 */
public class UUIDKeyGenerator implements StringKeyGenerator {
    @Override
    public String generateKey() {
        return UUID.randomUUID().toString().toLowerCase();
    }
}
