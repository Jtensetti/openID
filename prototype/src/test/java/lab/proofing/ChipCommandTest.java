package lab.proofing;

import java.io.*;
import java.nio.charset.StandardCharsets;
import net.sf.scuba.smartcards.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ChipCommandTest {
  ChipCommand.Relay relay(String reply) {
    var relay=new ChipCommand.Relay(new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)),new PrintStream(new ByteArrayOutputStream()));
    relay.open(); return relay;
  }
  @Test void rejectsWrongSequenceMalformedAndDuplicateFields() {
    for(String reply : new String[]{"{\"sequence\":1,\"response\":\"kAA=\"}\n",
        "{\"sequence\":true,\"response\":\"kAA=\"}\n", "{\"sequence\":0,\"response\":\"AA==\"}\n",
        "{\"sequence\":0,\"sequence\":0,\"response\":\"kAA=\"}\n", "{}\n", "x".repeat(8193)})
      assertThrows(CardServiceException.class,()->relay(reply).transmit(new CommandAPDU(0,0xA4,0,0)));
  }
  @Test void refusesWriteInstructionsAndUnknownClasses() {
    for(int instruction : new int[]{0xD0,0xD6,0xDA,0xE0,0xE4,0x20,0x24})
      assertThrows(CardServiceException.class,()->relay("{\"sequence\":0,\"response\":\"kAA=\"}\n").transmit(new CommandAPDU(0,instruction,0,0)));
    assertThrows(CardServiceException.class,()->relay("").transmit(new CommandAPDU(0x80,0xA4,0,0)));
  }
  @Test void boundedLineRequiresNewlineAndUniqueFields() {
    assertThrows(IOException.class,()->ChipCommand.line(new ByteArrayInputStream("{}".getBytes()),5));
    assertThrows(IOException.class,()->ChipCommand.line(new ByteArrayInputStream("123456\n".getBytes()),5));
  }
}
