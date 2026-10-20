package lab.proofing;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import net.sf.scuba.smartcards.*;
import net.sf.scuba.tlv.*;
import org.jmrtd.*;
import org.jmrtd.lds.*;
import org.jmrtd.protocol.*;

/** Test-only PACE/CA peer using JMRTD key agreement and JCA/BC ciphers/MACs. */
final class SoftwarePassportChip extends CardService {
  static final String PACE = SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128;
  static final String CA = SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256;
  final byte[] cardAccess = new CardAccessFile(List.of(new PACEInfo(PACE, 2, 12))).getEncoded();
  final KeyPair chipKey;
  final byte[] dg14;
  final BACKey accessKey;
  private boolean open;
  private int stage;
  private byte[] nonce;
  private ECParameterSpec mapped;
  private PublicKey terminalKey;
  private KeyPair ephemeral;
  private SecretKey enc, mac;
  private long ssc;
  private boolean caComplete;
  final List<byte[]> proofs = new ArrayList<>();
  List<byte[]> replay;
  boolean corruptMac, wrongData, bareSuccess, rejectPace;

  SoftwarePassportChip(KeyPair chipKey, byte[] dg14, BACKey accessKey) {
    this.chipKey = chipKey; this.dg14 = dg14; this.accessKey = accessKey;
  }
  @Override public void open() { open = true; }
  @Override public boolean isOpen() { return open; }
  @Override public void close() { open = false; }
  @Override public byte[] getATR() { return new byte[0]; }
  @Override public boolean isConnectionLost(Exception e) { return true; }

  @Override public ResponseAPDU transmit(CommandAPDU command) throws CardServiceException {
    try {
      if (stage == 0) {
        if (command.getINS() == 0xA4) return ok(new byte[0]);
        if (command.getINS() == 0xB0) {
          int offset = (command.getP1() << 8) | command.getP2();
          return ok(Arrays.copyOfRange(cardAccess, offset, Math.min(cardAccess.length, offset + command.getNe())));
        }
        if (command.getINS() == 0x22) { stage = 1; return ok(new byte[0]); }
      }
      if (stage <= 4 && command.getINS() == 0x86) return pace(command);
      if (stage != 5 || (command.getCLA() & 0x0C) != 0x0C) throw new GeneralSecurityException();
      byte[] body = unwrap(command);
      if (command.getINS() == 0x22) return protectedReply(new byte[0]);
      if (command.getINS() == 0x86) {
        var point = TLVUtil.unwrapDO(0x80, TLVUtil.unwrapDO(0x7C, body));
        var publicKey = PACEProtocol.decodePublicKeyFromSmartCard(point,
            ((java.security.interfaces.ECPublicKey)chipKey.getPublic()).getParams());
        byte[] secret = EACCAProtocol.computeSharedSecret("ECDH", publicKey, chipKey.getPrivate());
        var reply = protectedReply(TLVUtil.wrapDO(0x7C, new byte[0]));
        var wrapper = EACCAProtocol.restartSecureMessaging(CA, secret, 256, true);
        enc = wrapper.getEncryptionKey(); mac = wrapper.getMACKey(); ssc = 0; caComplete = true;
        return reply;
      }
      if (caComplete && replay != null) return new ResponseAPDU(replay.get(proofs.size()));
      if (caComplete && bareSuccess) return ok(new byte[0]);
      byte[] data = command.getINS() == 0xB0 ? Arrays.copyOf(dg14, Math.min(64, dg14.length)) : new byte[0];
      if (caComplete && wrongData && data.length > 0) data[0] ^= 1;
      var response = protectedReply(data);
      if (caComplete) {
        proofs.add(response.getBytes());
        if (corruptMac) {
          byte[] modified = response.getBytes(); modified[modified.length - 3] ^= 1;
          return new ResponseAPDU(modified);
        }
      }
      return response;
    } catch (Exception e) { throw new CardServiceException("Software chip rejected exchange", e); }
  }

  private ResponseAPDU pace(CommandAPDU command) throws Exception {
    if (rejectPace) return new ResponseAPDU(new byte[]{0x63, 0x00});
    byte[] data = TLVUtil.unwrapDO(0x7C, command.getData());
    byte[] response;
    var params = (ECParameterSpec)PACEInfo.toParameterSpec(12);
    if (stage == 1) {
      nonce = new byte[16]; new SecureRandom().nextBytes(nonce);
      var cipher = Util.getCipher("AES/CBC/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, PACEProtocol.deriveStaticPACEKey(accessKey, PACE), new IvParameterSpec(new byte[16]));
      response = TLVUtil.wrapDO(0x80, cipher.doFinal(nonce));
    } else if (stage == 2) {
      var terminal = PACEProtocol.decodePublicKeyFromSmartCard(TLVUtil.unwrapDO(0x81, data), params);
      var generator = Util.getKeyPairGenerator("ECDH"); generator.initialize(params);
      var mappingKey = generator.generateKeyPair();
      var agreement = new PACEGMWithECDHAgreement(); agreement.init(mappingKey.getPrivate());
      mapped = PACEProtocol.mapNonceGMWithECDH(nonce, agreement.doPhase(terminal), params);
      response = TLVUtil.wrapDO(0x82, PACEProtocol.encodePublicKeyForSmartCard(mappingKey.getPublic()));
    } else if (stage == 3) {
      terminalKey = PACEProtocol.decodePublicKeyFromSmartCard(TLVUtil.unwrapDO(0x83, data), mapped);
      var generator = Util.getKeyPairGenerator("ECDH"); generator.initialize(mapped); ephemeral = generator.generateKeyPair();
      byte[] secret = EACCAProtocol.computeSharedSecret("ECDH", terminalKey, ephemeral.getPrivate());
      enc = Util.deriveKey(secret, "AES", 128, Util.ENC_MODE);
      mac = Util.deriveKey(secret, "AES", 128, Util.MAC_MODE);
      response = TLVUtil.wrapDO(0x84, PACEProtocol.encodePublicKeyForSmartCard(ephemeral.getPublic()));
    } else {
      if (!MessageDigest.isEqual(TLVUtil.unwrapDO(0x85, data),
          PACEProtocol.generateAuthenticationToken(PACE, mac, ephemeral.getPublic()))) throw new GeneralSecurityException();
      response = TLVUtil.wrapDO(0x86, PACEProtocol.generateAuthenticationToken(PACE, mac, terminalKey));
      ssc = 0;
    }
    stage++;
    return ok(TLVUtil.wrapDO(0x7C, response));
  }

  private byte[] unwrap(CommandAPDU command) throws Exception {
    ssc++;
    var objects = new TLVInputStream(new ByteArrayInputStream(command.getData()));
    byte[] encrypted = null, signature = null;
    var authenticated = new ByteArrayOutputStream();
    authenticated.write(Util.pad(Arrays.copyOf(command.getBytes(), 4), 16));
    while (objects.available() > 0) {
      int tag = objects.readTag(); objects.readLength(); byte[] value = objects.readValue();
      if (tag == 0x8E) signature = value;
      else authenticated.write(TLVUtil.wrapDO(tag, value));
      if (tag == 0x87) encrypted = value;
    }
    if (!MessageDigest.isEqual(signature, cmac(concat(counter(), Util.pad(authenticated.toByteArray(), 16)))))
      throw new GeneralSecurityException();
    if (encrypted == null) return new byte[0];
    var cipher = Util.getCipher("AES/CBC/NoPadding"); cipher.init(Cipher.DECRYPT_MODE, enc, iv());
    return Util.unpad(cipher.doFinal(Arrays.copyOfRange(encrypted, 1, encrypted.length)));
  }

  private ResponseAPDU protectedReply(byte[] data) throws Exception {
    ssc++;
    byte[] body = new byte[0];
    if (data.length > 0) {
      var cipher = Util.getCipher("AES/CBC/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, enc, iv());
      body = TLVUtil.wrapDO(0x87, concat(new byte[]{1}, cipher.doFinal(Util.pad(data, 16))));
    }
    body = concat(body, new byte[]{(byte)0x99, 2, (byte)0x90, 0});
    byte[] signature = cmac(concat(counter(), Util.pad(body, 16)));
    return ok(concat(body, TLVUtil.wrapDO(0x8E, signature)));
  }
  private byte[] cmac(byte[] bytes) throws Exception {
    var engine = Util.getMac("AESCMAC"); engine.init(mac);
    return Arrays.copyOf(engine.doFinal(bytes), 8);
  }
  private byte[] counter() { return ByteBuffer.allocate(16).putLong(0).putLong(ssc).array(); }
  private IvParameterSpec iv() throws Exception {
    var cipher = Util.getCipher("AES/ECB/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, enc);
    return new IvParameterSpec(cipher.doFinal(counter()));
  }
  private static ResponseAPDU ok(byte[] data) { return new ResponseAPDU(concat(data, new byte[]{(byte)0x90, 0})); }
  private static byte[] concat(byte[] a, byte[] b) {
    byte[] result = Arrays.copyOf(a, a.length + b.length); System.arraycopy(b, 0, result, a.length, b.length); return result;
  }
}
