/**
 * A small, valid, multi-page PDF built byte-for-byte, so tests publish a real
 * document without a binary fixture. Each page draws its lines of text in
 * Helvetica; the cross-reference table records exact object offsets.
 *
 * Object layout: 1 catalog, 2 page tree, 3 document info, then one page and
 * one content stream per page, then the shared font.
 */
export function multiPagePdf(pages: readonly (readonly string[])[]): Uint8Array {
  if (pages.length === 0) throw new Error("A PDF fixture needs at least one page.");
  const fontObject = 4 + pages.length * 2;
  const objects: string[] = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    `<< /Type /Pages /Kids [${pages.map((_, index) => `${pageObject(index)} 0 R`).join(" ")}] /Count ${pages.length} >>`,
    "<< /Producer (Artifact Server tests) >>",
  ];
  pages.forEach((lines, index) => {
    const content = [
      "BT",
      "/F1 24 Tf",
      "72 720 Td",
      "28 TL",
      ...lines.map((line) => `(${escapePdfText(line)}) Tj T*`),
      "ET",
    ].join("\n");
    objects.push(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 ${fontObject} 0 R >> >> /Contents ${pageObject(index) + 1} 0 R >>`,
      `<< /Length ${content.length} >>\nstream\n${content}\nendstream`,
    );
  });
  objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");

  let body = "%PDF-1.4\n";
  const offsets: number[] = [];
  objects.forEach((object, index) => {
    offsets.push(body.length);
    body += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xrefOffset = body.length;
  body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets) {
    body += `${String(offset).padStart(10, "0")} 00000 n \n`;
  }
  body += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R /Info 3 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  return new TextEncoder().encode(body);
}

/** The object number of a page; its content stream follows it. */
function pageObject(index: number): number {
  return 4 + index * 2;
}

/** Printable ASCII only, so string length equals byte length in the offsets. */
function escapePdfText(text: string): string {
  if (!/^[\x20-\x7e]*$/u.test(text)) {
    throw new Error("PDF fixture text must be printable ASCII.");
  }
  return text.replace(/[\\()]/gu, (character) => `\\${character}`);
}
