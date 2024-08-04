import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.example.Main;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.interfaces.RSAKey;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

public class GenerateKeySetTest {


    @Test
    void verify() throws IOException, URISyntaxException, ParseException, BadJOSEException, JOSEException{
        var token = "eyJraWQiOiI2MTcyZmExOS1lNTM3LTRjYTItYWZjMi1jOTZmMGJjOGUzYzYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSIsInNjcCI6IlJPTEVfVVNFUiwgUk9MRV9BRE1JTiIsImV4cCI6MTcyMjg3MDA3MiwianRpIjoiMzhhNTJjZjUtMTA0Yi00YWM2LWI1NmYtZmYzZmU3OWYyNjc1In0.qGCEZ8RzokbNBeX-z3rkbOXqLlhu57VKw21yuT5UMlZpVawMcXK8kLcVCthjTieQZR_9_C66N75LitHYHxgH26xoxQN6YT9iw2_wJ5Xwi0Cy37jNkq9xd1ZxHdUgbriaBKVBI3hCzc3iSomXXW8KD7wWXK3F9Vy4mfxk3YaAaQCWxgYfIc3BeOvlNEdb0EysPO1DCaUD775FKpk7cTPe_7mUHgATMPbXK25HH-vnwayS4u46b6X9DadwkgJDS3d-csFptKt7mCZq_VCv_9cIhphEqtDNzTLE_YTWJ3WJuYOXoDqkREhddY9pDv-7LsBBiB-TwO8ReSxQJEvqJVYOwg";
        var claimSet = Main.jwtProcessor.process(token,null);
        System.out.println(claimSet);
    }


    @Test
    void generateKeySetAndToken() throws JOSEException{
        var jwk1 = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        var jwk2 = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();

        System.out.println(jwk1.toPrivateKey().toString());

        var jwks= "{\"keys\":[" + jwk2.toPublicJWK() + "," + jwk1.toPublicJWK() + "]}";

        var claimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .jwtID(UUID.randomUUID().toString())
                .claim("scp","ROLE_USER, ROLE_ADMIN")
                .expirationTime(new Date(new Date().getTime() + 24 * 60 * 60 * 1000))
                .build();
        var signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(jwk1.getKeyID())
                        .build(),
                claimsSet
        );

        signedJWT.sign(new RSASSASigner(jwk1));
        var token = signedJWT.serialize();

        System.out.println("keyset:\n" + jwks);
        System.out.println("token:\n" + token);
    }

}
