package org.paseto4j.version4;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class CryptoFunctions {
  private CryptoFunctions() {}

  public static byte[] sign(PrivateKey privateKey, byte[] msg) {
    try {
      Signature signature = Signature.getInstance("Ed25519", "BC");
      signature.initSign(privateKey);
      signature.update(msg);
      return signature.sign();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public static boolean verify(PublicKey publicKey, byte[] msg, byte[] signature) {
    try {
      Signature verifier = Signature.getInstance("Ed25519", "BC");
      verifier.initVerify(publicKey);
      verifier.update(msg);

      return verifier.verify(signature);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }
}
