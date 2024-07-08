package org.paseto4j.version4;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.Conditions.verify;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;
import static org.paseto4j.commons.Version.V4;

import java.security.MessageDigest;
import java.util.Arrays;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.sodium.GenericHash;
import org.apache.tuweni.crypto.sodium.XChaCha20;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.Token;
import org.paseto4j.commons.TokenOut;

public class PasetoLocal {
  private PasetoLocal() {}

  public static String encrypt(SecretKey key, String payload, String footer, String implicit) {
    return encrypt(key, Bytes.random(32).toArray(), payload, footer, implicit);
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#encrypt
   */
  static String encrypt(
      SecretKey key, byte[] nonce, String payload, String footer, String implicitAssertion) {
    requireNonNull(key);
    requireNonNull(payload);
    verify(key.isValidFor(V4, PURPOSE_LOCAL), "Key is not valid for purpose and version");
    verify(key.hasLength(32), "key should be 32 bytes");
    verify(nonce.length == 32, "nonce should be 32 bytes");

    TokenOut token = new TokenOut(V4, PURPOSE_LOCAL);

    // 4
    byte[] tmp = encryptionKey(key, nonce);
    byte[] ek = Arrays.copyOfRange(tmp, 0, 32);
    byte[] n2 = Arrays.copyOfRange(tmp, 32, 56);
    byte[] ak = authenticationKey(key, nonce);

    // 5
    byte[] c = XChaCha20.encrypt(payload.getBytes(UTF_8), n2, ek);

    // 6
    byte[] preAuth =
        PreAuthenticationEncoder.encode(
            token.header(), nonce, c, footer.getBytes(UTF_8), implicitAssertion.getBytes(UTF_8));

    // 7
    byte[] t =
        GenericHash.hash(32, GenericHash.Input.fromBytes(preAuth), GenericHash.Key.fromBytes(ak))
            .bytesArray();

    return token.payload(concat(nonce, c, t)).footer(footer).doFinal();
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#decrypt
   */
  static String decrypt(SecretKey key, String token, String footer, String implicitAssertion) {
    requireNonNull(key);
    requireNonNull(token);

    verify(key.isValidFor(V4, PURPOSE_LOCAL), "Key is not valid for purpose and version");
    verify(key.hasLength(32), "key should be 32 bytes");

    Token pasetoToken = new Token(token, V4, PURPOSE_LOCAL, footer);

    // 4
    byte[] nct = getUrlDecoder().decode(pasetoToken.getPayload());
    byte[] nonce = Arrays.copyOfRange(nct, 0, 32);
    byte[] t = Arrays.copyOfRange(nct, nct.length - 32, nct.length);
    byte[] c = Arrays.copyOfRange(nct, 32, nct.length - 32);

    // 5
    byte[] tmp = encryptionKey(key, nonce);
    byte[] ek = Arrays.copyOfRange(tmp, 0, 32);
    byte[] n2 = Arrays.copyOfRange(tmp, 32, 56);
    byte[] ak = authenticationKey(key, nonce);

    // 6
    byte[] preAuth =
        PreAuthenticationEncoder.encode(
            pasetoToken.header(),
            nonce,
            c,
            footer.getBytes(UTF_8),
            implicitAssertion.getBytes(UTF_8));

    // 7
    byte[] t2 =
        GenericHash.hash(32, GenericHash.Input.fromBytes(preAuth), GenericHash.Key.fromBytes(ak))
            .bytesArray();

    // 8
    if (!MessageDigest.isEqual(t, t2)) {
      throw new IllegalStateException("HMAC verification failed");
    }

    byte[] message = XChaCha20.encrypt(c, n2, ek);

    return new String(message, UTF_8);
  }

  private static byte[] encryptionKey(SecretKey key, byte[] nonce) {
    return GenericHash.hash(
            56,
            GenericHash.Input.fromBytes(concat("paseto-encryption-key".getBytes(UTF_8), nonce)),
            GenericHash.Key.fromBytes(key.getMaterial()))
        .bytesArray();
  }

  private static byte[] authenticationKey(SecretKey key, byte[] nonce) {
    return GenericHash.hash(
            32,
            GenericHash.Input.fromBytes(concat("paseto-auth-key-for-aead".getBytes(UTF_8), nonce)),
            GenericHash.Key.fromBytes(key.getMaterial()))
        .bytesArray();
  }
}
