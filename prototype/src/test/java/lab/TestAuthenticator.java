package lab;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.upokecenter.cbor.CBORObject;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import java.util.function.Consumer;

/** Synthetic authenticator test fixture. Every hash, random value and signature comes from JCA. */
final class TestAuthenticator {
  static final ObjectMapper JSON = new ObjectMapper();
  final KeyPair key;
  final byte[] id = new byte[32];
  String userHandle;
  String origin = "https://localhost:8443";
  TestAuthenticator() throws Exception {
    var generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1")); key = generator.generateKeyPair();
    new SecureRandom().nextBytes(id);
  }
  String registration(String options) throws Exception { return registration(options, 0x45, "localhost", c -> {}); }
  String registration(String options, int flags, String rp, Consumer<ObjectNode> change) throws Exception {
    JsonNode request = JSON.readTree(options).get("publicKey");
    userHandle = request.get("user").get("id").asText();
    byte[] client = client(request, "webauthn.create", change);
    var ec = (ECPublicKey) key.getPublic();
    var cose = CBORObject.NewMap().Add(1, 2).Add(3, -7).Add(-1, 1)
        .Add(-2, coordinate(ec.getW().getAffineX())).Add(-3, coordinate(ec.getW().getAffineY()));
    var data = new ByteArrayOutputStream();
    data.write(authData(rp, flags, 0)); data.write(new byte[16]);
    data.write(ByteBuffer.allocate(2).putShort((short) id.length).array()); data.write(id); data.write(cose.EncodeToBytes());
    var attestation = CBORObject.NewMap().Add("fmt", "none").Add("authData", data.toByteArray()).Add("attStmt", CBORObject.NewMap());
    ObjectNode result = base();
    result.putObject("response").put("clientDataJSON", b64(client)).put("attestationObject", b64(attestation.EncodeToBytes()))
        .putArray("transports").add("usb");
    return JSON.writeValueAsString(result);
  }
  String assertion(String options, long count) throws Exception { return assertion(options, count, 0x05, "localhost", c -> {}); }
  String assertion(String options, long count, int flags, String rp, Consumer<ObjectNode> change) throws Exception {
    byte[] client = client(JSON.readTree(options).get("publicKey"), "webauthn.get", change);
    byte[] authenticator = authData(rp, flags, count);
    Signature signer = Signature.getInstance("SHA256withECDSA"); signer.initSign(key.getPrivate());
    signer.update(authenticator); signer.update(hash(client));
    ObjectNode result = base();
    result.putObject("response").put("clientDataJSON", b64(client)).put("authenticatorData", b64(authenticator))
        .put("signature", b64(signer.sign())).put("userHandle", userHandle);
    return JSON.writeValueAsString(result);
  }
  private ObjectNode base() {
    ObjectNode root = JSON.createObjectNode().put("id", b64(id)).put("rawId", b64(id)).put("type", "public-key");
    root.putObject("clientExtensionResults"); return root;
  }
  private byte[] client(JsonNode options, String type, Consumer<ObjectNode> change) throws Exception {
    var data = JSON.createObjectNode().put("type", type).put("challenge", options.get("challenge").asText())
        .put("origin", origin).put("crossOrigin", false);
    change.accept(data); return JSON.writeValueAsBytes(data);
  }
  private static byte[] authData(String rp, int flags, long count) throws Exception {
    return ByteBuffer.allocate(37).put(hash(rp.getBytes(StandardCharsets.UTF_8))).put((byte) flags).putInt((int) count).array();
  }
  private static byte[] hash(byte[] bytes) throws Exception { return MessageDigest.getInstance("SHA-256").digest(bytes); }
  static String b64(byte[] bytes) { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
  private static byte[] coordinate(BigInteger n) {
    byte[] bytes = n.toByteArray(), out = new byte[32];
    System.arraycopy(bytes, Math.max(0, bytes.length - 32), out, Math.max(0, 32 - bytes.length), Math.min(bytes.length, 32)); return out;
  }
}
