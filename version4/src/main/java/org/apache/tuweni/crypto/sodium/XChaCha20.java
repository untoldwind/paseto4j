package org.apache.tuweni.crypto.sodium;

public final class XChaCha20 {
  public static boolean isAvailable() {
    try {
      return Sodium.supportsVersion(Sodium.VERSION_10_0_12);
    } catch (UnsatisfiedLinkError e) {
      return false;
    }
  }

  private static void assertAvailable() {
    if (!isAvailable()) {
      throw new UnsupportedOperationException(
          "Sodium XChaCha20 is not available (requires sodium native library >= 10.0.12)");
    }
  }

  public static byte[] encrypt(byte[] message, byte[] nonce, byte[] key) {
    assertAvailable();

    byte[] cipherText = new byte[message.length];
    Sodium.crypto_stream_xchacha20_xor(cipherText, message, message.length, nonce, key);

    return cipherText;
  }
}
