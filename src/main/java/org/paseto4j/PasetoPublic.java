package org.paseto4j;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.base.Verify;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import net.consensys.cava.crypto.sodium.CryptoCavaWrapper;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import java.security.*;
import java.util.Arrays;

import static com.google.common.io.BaseEncoding.base64Url;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Base64.getUrlEncoder;
import static org.paseto4j.Purpose.PUBLIC;

class PasetoPublic {

    static {
        Security.addProvider(new EdDSASecurityProvider());
    }

    /**
     * Sign the token, https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#sign
     */
    static String sign(byte[] privateKey, String payload, String footer) {
        Preconditions.checkNotNull(privateKey);
        Preconditions.checkNotNull(payload);
        Preconditions.checkArgument(privateKey.length == 32 || privateKey.length == 64, "Private key should be 32 or 64 bytes");

        byte[] m2 = BaseEncoding.base16().lowerCase().decode(Util.pae(PUBLIC.toString(), payload, footer));
        byte[] signature = sign(privateKey, m2);

        String signedToken = PUBLIC + getUrlEncoder().withoutPadding().encodeToString(Bytes.concat(payload.getBytes(UTF_8), signature));

        if (!Strings.isNullOrEmpty(footer)) {
            signedToken = signedToken + "." + base64Url().encode(footer.getBytes(UTF_8));
        }
        return signedToken;
    }

    //https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/
    private static byte[] sign(byte[] key, byte[] message) {
        byte[] result = new byte[64];
        byte[] secretKey = new byte[64];
        if (key.length == 32) {
            byte[] pk = new byte[64];
            CryptoCavaWrapper.crypto_sign_ed25519_seed_keypair(key, pk, secretKey);
        } else {
            secretKey = key;
        }
        CryptoCavaWrapper.crypto_sign_detached(result, message, secretKey);
        return result;
    }

    /**
     * Parse the token, https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#verify
     */
    static String parse(byte[] publicKey, String signedMessage, String footer) {
        Preconditions.checkNotNull(publicKey);
        Preconditions.checkNotNull(signedMessage);
        Preconditions.checkArgument(publicKey.length == 32 || publicKey.length == 64, "Public key should be 32 bytes");

        String[] tokenParts = signedMessage.split("\\.");

        //1
        if (!Strings.isNullOrEmpty(footer)) {
            Verify.verify(Arrays.equals(getUrlDecoder().decode(tokenParts[3]), footer.getBytes(UTF_8)), "footer does not match");
        }

        //2
        Verify.verify(signedMessage.startsWith(PUBLIC.toString()), "Token should start with " + PUBLIC);

        //3
        byte[] sm = getUrlDecoder().decode(tokenParts[2]);
        byte[] signature = Arrays.copyOfRange(sm, sm.length - 64, sm.length);
        byte[] message = Arrays.copyOfRange(sm, 0, sm.length - 64);

        //4
        byte[] m2 = Util.pae(PUBLIC.toString().getBytes(UTF_8), message, footer.getBytes(UTF_8));

        //5
        verify(publicKey, m2, signature);

        return new String(message);
    }

    private static void verify(byte[] key, byte[] message, byte[] signature) {
        int valid = CryptoCavaWrapper.crypto_sign_verify_detached(signature, message, key);
        if (valid != 0) {
            throw new RuntimeException("Invalid signature");
        }
    }

}
