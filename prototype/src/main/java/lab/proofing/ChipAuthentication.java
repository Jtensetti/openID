package lab.proofing;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Objects;
import java.util.Set;
import org.jmrtd.BACKey;
import org.jmrtd.PassportService;
import org.jmrtd.lds.CardAccessFile;
import org.jmrtd.lds.ChipAuthenticationInfo;
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.lds.icao.DG14File;
import org.jmrtd.protocol.ReadBinaryAPDUSender;

public final class ChipAuthentication {
  private static final Set<String> CA = Set.of(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128,
      SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_192, SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256);
  private static final Set<String> PACE = Set.of(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
      SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192, SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256);

  public record Document(PassportVerifier.Result identity, ChipAuthenticationInfo protocol,
      ChipAuthenticationPublicKeyInfo key, byte[] dg14) {
    public Document { dg14 = dg14.clone(); }
    @Override public byte[] dg14() { return dg14.clone(); }
  }

  public static Document verifyDocument(PassportVerifier verifier, byte[] sod, byte[] dg1,
      byte[] dg2, byte[] dg14) throws Exception {
    var identity = verifier.verify(sod, dg1, dg2);
    if (dg14.length == 0 || dg14.length > 16384) throw new PassportVerifier.Rejected();
    var security = new SODFile(new ByteArrayInputStream(sod));
    var expected = security.getDataGroupHashes().get(14);
    if (expected == null || !MessageDigest.isEqual(expected,
        MessageDigest.getInstance(security.getDigestAlgorithm()).digest(dg14))) throw new PassportVerifier.Rejected();
    var input = new ByteArrayInputStream(dg14);
    var group = new DG14File(input);
    if (input.available() != 0) throw new PassportVerifier.Rejected();
    var protocol = group.getChipAuthenticationInfos().stream()
        .filter(info -> info.getVersion() == 1 && CA.contains(info.getObjectIdentifier()))
        .max(Comparator.comparingInt(info -> ChipAuthenticationInfo.toKeyLength(info.getObjectIdentifier())))
        .orElseThrow(PassportVerifier.Rejected::new);
    var keys = group.getChipAuthenticationPublicKeyInfos().stream()
        .filter(key -> Objects.equals(key.getKeyId(), protocol.getKeyId())
            && SecurityInfo.ID_PK_ECDH.equals(key.getObjectIdentifier())).toList();
    if (keys.size() != 1 || !(keys.getFirst().getSubjectPublicKey() instanceof ECPublicKey key)
        || key.getParams().getOrder().bitLength() < 256 || key.getParams().getOrder().bitLength() > 521)
      throw new PassportVerifier.Rejected();
    return new Document(identity, protocol, keys.getFirst(), dg14);
  }

  public static void authenticate(PassportService service, Document document) throws Exception {
    if (!service.shouldCheckMAC()) throw new PassportVerifier.Rejected();
    service.open();
    service.sendSelectMF();
    byte[] access;
    try (var stream = service.getInputStream(PassportService.EF_CARD_ACCESS, 223)) {
      access = stream.readNBytes(4097);
    }
    if (access.length == 0 || access.length > 4096) throw new PassportVerifier.Rejected();
    var input = new ByteArrayInputStream(access);
    var infos = new CardAccessFile(input).getSecurityInfos();
    if (input.available() != 0) throw new PassportVerifier.Rejected();
    var pace = infos.stream().filter(PACEInfo.class::isInstance).map(PACEInfo.class::cast)
        .filter(info -> info.getVersion() == 2 && PACE.contains(info.getObjectIdentifier())
            && info.getParameterId() != null && info.getParameterId().bitLength() < 8
            && info.getParameterId().intValue() >= 12 && info.getParameterId().intValue() <= 18)
        .max(Comparator.comparingInt(info -> PACEInfo.toKeyLength(info.getObjectIdentifier())))
        .orElseThrow(PassportVerifier.Rejected::new);
    var person = document.identity().identity();
    var key = new BACKey(person.documentNumber(), person.birthDateMrz(),
        document.identity().expires().format(java.time.format.DateTimeFormatter.ofPattern("yyMMdd")));
    service.doPACE(key, pace.getObjectIdentifier(), PACEInfo.toParameterSpec(pace.getParameterId()), pace.getParameterId());
    service.sendSelectApplet(true);
    provePossession(service, document);
  }

  static void provePossession(PassportService service, Document document) throws Exception {
    if (!service.shouldCheckMAC()) throw new PassportVerifier.Rejected();
    var protocol = document.protocol();
    service.doEACCA(protocol.getKeyId(), protocol.getObjectIdentifier(),
        document.key().getObjectIdentifier(), document.key().getSubjectPublicKey());
    var wrapper = service.getWrapper();
    if (wrapper == null || !wrapper.shouldCheckMAC()) throw new PassportVerifier.Rejected();
    // CA v1 establishes keys without confirming possession. A fresh, MAC-checked
    // read proves the chip used its private key; do not use the file-system cache.
    var reader = new ReadBinaryAPDUSender(service.getSecureMessagingAPDUSender());
    reader.sendSelectFile(wrapper, PassportService.EF_DG14);
    int length = Math.min(64, document.dg14().length);
    byte[] actual = reader.sendReadBinary(wrapper, 0, 0, length, false, false);
    if (!MessageDigest.isEqual(Arrays.copyOf(document.dg14(), length), actual))
      throw new PassportVerifier.Rejected();
  }
}
