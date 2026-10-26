package lab.signing;

import java.awt.Color;
import java.io.IOException;
import java.time.*;
import java.time.format.DateTimeFormatter;
import org.apache.pdfbox.pdmodel.*;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.*;
import org.apache.pdfbox.pdmodel.interactive.annotation.*;
import org.apache.pdfbox.pdmodel.interactive.form.*;

/** A visible receipt on the actual PDF signature field, covered by the same signed byte range. */
final class SignatureAppearance {
  static final String FIELD = "openIDTestSignature";
  private static final float WIDTH = 475, HEIGHT = 275;
  private static final Color INK = new Color(15, 41, 48), PAPER = new Color(246, 247, 243);
  private SignatureAppearance() {}

  /** Reserve space in the original document, before its hash is shown to the holder. */
  static void reserve(PDDocument document, PDPage page) throws IOException {
    var form = new PDAcroForm(document);
    document.getDocumentCatalog().setAcroForm(form);
    form.setNeedAppearances(false);
    var field = new PDSignatureField(form);
    field.setPartialName(FIELD);
    form.getFields().add(field);
    var widget = field.getWidgets().getFirst();
    widget.setRectangle(new PDRectangle(60, 60, WIDTH, HEIGHT));
    widget.setPage(page); widget.setPrinted(true);
    page.getAnnotations().add(widget);
  }

  /** This service signs its own one-page templates, never overlays an arbitrary uploaded document. */
  static PDSignatureField reservedField(PDDocument document) throws IOException {
    var form = document.getDocumentCatalog().getAcroForm();
    if (document.getNumberOfPages() != 1 || form == null || form.getFields().size() != 1
        || !(form.getField(FIELD) instanceof PDSignatureField field) || field.getSignature() != null
        || field.getWidgets().size() != 1) throw new IOException("Reserved unsigned signature field required");
    return field;
  }

  static void draw(PDDocument document, PDSignatureField field, String name, Instant at,
      String reference, String originalHash) throws IOException {
    var appearance = new PDAppearanceStream(document);
    appearance.setResources(new PDResources());
    appearance.setBBox(new PDRectangle(WIDTH, HEIGHT));
    PDFont regular = new PDType1Font(Standard14Fonts.FontName.HELVETICA),
        bold = new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD),
        mono = new PDType1Font(Standard14Fonts.FontName.COURIER);
    try (var c = new PDPageContentStream(document, appearance)) {
      c.setNonStrokingColor(PAPER); c.addRect(0, 0, WIDTH, HEIGHT); c.fill();
      c.setNonStrokingColor(INK); c.addRect(0, HEIGHT - 42, WIDTH, 42); c.fill();
      c.setNonStrokingColor(Color.WHITE);
      text(c, bold, 13, 18, HEIGHT - 26, "openID  /  UNDERSKRIFTSKVITTO");
      c.setNonStrokingColor(new Color(132, 77, 12));
      text(c, bold, 9, 18, HEIGHT - 60, "TESTUNDERSKRIFT - EJ BETRODD UTFÄRDARE");
      c.setNonStrokingColor(INK);
      float y = HEIGHT - 80;
      text(c, regular, 8, 18, y, "UNDERTECKNARE"); y -= 17;
      // MRZ names may contain one very long token. Wrap by measured glyph width, never truncate the signer.
      String rest = name;
      while (!rest.isEmpty()) {
        int end = rest.length();
        while (bold.getStringWidth(rest.substring(0, end)) / 1000 * 12 > WIDTH - 36) end--;
        text(c, bold, 12, 18, y, rest.substring(0, end)); y -= 16;
        rest = rest.substring(end);
      }
      y -= 4;
      String time = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z").format(at.atZone(ZoneId.of("Europe/Stockholm")));
      text(c, regular, 9, 18, y, "Tid enligt serverklockan: " + time); y -= 15;
      text(c, mono, 8, 18, y, "Underskriftsreferens: " + reference); y -= 23;
      text(c, regular, 8, 18, y, "ORIGINALDOKUMENTETS SHA-256"); y -= 13;
      text(c, mono, 8, 18, y, originalHash); y -= 23;
      text(c, regular, 9, 18, y, "Utseendet kan kopieras. Kontrollera PDF:ens digitala signatur."); y -= 14;
      text(c, regular, 9, 18, y, "Test-CA, utan betrodd tidsstämpel eller rättslig verkan.");
      c.setStrokingColor(new Color(205, 213, 210)); c.setLineWidth(0.8f);
      c.addRect(0.4f, 0.4f, WIDTH - 0.8f, HEIGHT - 0.8f); c.stroke();
    }
    var dictionary = new PDAppearanceDictionary(); dictionary.setNormalAppearance(appearance);
    var widget = field.getWidgets().getFirst();
    // addSignature creates an invisible rectangle unless a visual template is supplied. Restore the reserved area.
    widget.setRectangle(new PDRectangle(60, 60, WIDTH, HEIGHT));
    widget.setPage(document.getPage(0)); widget.setPrinted(true); widget.setAppearance(dictionary);
    widget.getCOSObject().setNeedToBeUpdated(true);
    field.getCOSObject().setNeedToBeUpdated(true);
    document.getPage(0).getCOSObject().setNeedToBeUpdated(true);
  }

  private static void text(PDPageContentStream c, PDFont font, float size, float x, float y, String value) throws IOException {
    c.beginText(); c.setFont(font, size); c.newLineAtOffset(x, y); c.showText(value); c.endText();
  }
}
