#!/usr/bin/env python3
"""Generate PDF and PPTX submission docs (stdlib only)."""

import os
import struct
import zipfile
import zlib
from datetime import datetime
from xml.sax.saxutils import escape

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "docs", "output")

# User prompts only (see docs/PROMPTS.md). No system notifications or duplicates.
PROMPTS = [
    ("1", "Assignment brief", "Rubric: HLD→LLD→Execution→Testing; provide all prompts; PDF/Doc/Video."),
    ("2", "can you create the code now?", ""),
    ("3", "can you create the c files with make file?", ""),
    ("4", "you understood the problem statement clearly?", ""),
    ("5", "IKEv2 LB + openiked + StrongSwan", "Hub-spoke; openiked-portable; StrongSwan interop."),
    ("6", "test plan and test it?", ""),
    ("7", "how many requests handled concurrently", ""),
    ("8", "configurable at build time", "IKE_LB_MAX_SESSIONS/BACKENDS/TIMEOUT defaults."),
    ("9", "is the python file inside src/ikev2", ""),
    ("10", "if not required remote", "Remove unused Python."),
    ("11", "generate ppt or pdf and prompt string", ""),
    ("12", "tcpdump and end to end testing", ""),
    ("13", "all the interop with algorithms flow tested", ""),
    ("14", "IKE interop: structure/algorithms vs other scenarios", ""),
    ("15", "update required vs optional scenarios", "INTEROP.md checklists."),
    ("16", "prompt log: required prompts only", "docs/PROMPTS.md"),
]

STEPS = [
    ("Requirements", "Rubric + openiked hub LB + StrongSwan spokes"),
    ("HLD/LLD", "docs/DESIGN.md — VIP, SPI stickiness"),
    ("Implementation", "ike-lb, ike_lb_pcap, Makefile, build-time limits"),
    ("Interop", "INTEROP.md — Required / Recommended / Optional"),
    ("Scalability", "DESIGN.md §5 — 65k sessions, 32 backends, scale-out path"),
    ("Testing", "30 unit tests; E2E + multi-session + PCAP + recording"),
    ("Practicality", "docs/PRACTICALITY.md — lab vs production, S-01–S-04"),
    ("Submission", "PDF/PPTX via make submission-docs"),
]


class SimplePDF:
    """Minimal PDF 1.4 writer (Helvetica, text only)."""

    def __init__(self):
        self.pages = []
        self._y = 800
        self._line = 14
        self._page_lines = []

    def _flush_page(self):
        if self._page_lines:
            self.pages.append(list(self._page_lines))
            self._page_lines = []
            self._y = 800

    def add_page(self):
        self._flush_page()

    def text(self, s, size=11, bold=False):
        font = "Helvetica-Bold" if bold else "Helvetica"
        if self._y < 50:
            self.add_page()
            self._y = 800
        self._page_lines.append((self._y, size, font, s))
        self._y -= self._line if size <= 11 else 18

    def build(self):
        self._flush_page()
        objects = []
        page_objs = []
        content_objs = []

        def add_obj(data):
            objects.append(data)
            return len(objects)

        font_reg = add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        font_bold = add_obj(
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"
        )

        for lines in self.pages:
            stream_parts = ["BT"]
            for y, size, font, txt in lines:
                fnum = font_bold if "Bold" in font else font_reg
                safe = txt.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
                stream_parts.append(f"/F{fnum} {size} Tf")
                stream_parts.append(f"50 {y} Td")
                stream_parts.append(f"({safe}) Tj")
                stream_parts.append(f"0 -{size + 4} Td")
            stream_parts.append("ET")
            stream_data = "\n".join(stream_parts).encode("latin-1", errors="replace")
            compressed = zlib.compress(stream_data)
            content = (
                f"<< /Length {len(compressed)} /Filter /FlateDecode >>\nstream\n".encode()
                + compressed
                + b"\nendstream"
            )
            content_objs.append(add_obj(content))

        for i, _ in enumerate(self.pages):
            page_objs.append(
                add_obj(
                    f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] "
                    f"/Contents {content_objs[i]} 0 R "
                    f"/Resources << /Font << /F{font_reg} {font_reg} 0 R /F{font_bold} {font_bold} 0 R >> >> >>".encode()
                )
            )

        kids = " ".join(f"{p} 0 R" for p in page_objs)
        pages_id = add_obj(f"<< /Type /Pages /Kids [{kids}] /Count {len(page_objs)} >>".encode())
        catalog_id = add_obj(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode())

        out = bytearray(b"%PDF-1.4\n")
        offsets = [0]

        for i, obj in enumerate(objects, 1):
            offsets.append(len(out))
            out.extend(f"{i} 0 obj\n".encode())
            out.extend(obj if obj.endswith(b"\n") else obj + b"\n")
            out.extend(b"endobj\n")

        xref_pos = len(out)
        out.extend(f"xref\n0 {len(objects)+1}\n".encode())
        out.extend(b"0000000000 65535 f \n")
        for off in offsets[1:]:
            out.extend(f"{off:010d} 00000 n \n".encode())
        out.extend(
            f"trailer\n<< /Size {len(objects)+1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n".encode()
        )
        return bytes(out)


def build_pdf():
    pdf = SimplePDF()
    pdf.text("IKEv2 Load Balancer - Project Report", bold=True)
    pdf.text(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", size=10)
    pdf.add_page()

    pdf.text("1. Executive Summary", bold=True)
    pdf.text(
        "IKE-aware UDP load balancer (ike-lb) for hub-spoke networks using "
        "openiked-portable on hubs and StrongSwan on spokes. SPI-based sticky "
        "sessions per RFC 7296."
    )
    pdf.add_page()

    pdf.text("2. Steps Completed", bold=True)
    for t, d in STEPS:
        pdf.text(f"  {t}", bold=True)
        pdf.text(f"    {d}", size=10)
    pdf.add_page()

    pdf.text("3. Architecture & Flow", bold=True)
    for line in [
        "  Spokes (StrongSwan) --IKE UDP 500/4500--> Hub VIP (ike-lb)",
        "       |",
        "       +-- hash(init SPI) --> iked backend 1..M (openiked)",
        "",
        "  IKE_SA_INIT: Spoke->VIP->LB picks backend->iked->response",
        "  IKE_AUTH+:   Spoke->VIP->lookup SPI->SAME backend",
        "  ESP traffic: kernel/IPsec (NOT through ike-lb)",
        "",
        "  Diagrams: docs/FLOWS.md (Mermaid sequence + flowcharts)",
    ]:
        pdf.text(line, size=10)
    pdf.add_page()

    pdf.text("4. Build & Test Results", bold=True)
    pdf.text("  make IKEV2_NO_SSL=1 && make show-config")
    pdf.text("  MAX_SESSIONS=65536  MAX_BACKENDS=32  TIMEOUT=3600s")
    pdf.text("  Unit tests: 31/31 PASS (msg, lb, proposals)")
    pdf.text("  E2E demo: run_tests.sh + multi-session 5/5 PASS")
    pdf.text("  Real interop S-01: run_interop_real.sh PASS (StrongSwan/charon)")
    pdf.add_page()

    pdf.text("5. Scalability", bold=True)
    pdf.text(
        "Horizontal: add openiked backends behind hub VIP; hash on Initiator SPI. "
        "Limits: 65536 sessions, 32 backends (build-time). "
        "Prototype: single-thread poll(), linear session lookup."
    )
    pdf.text(
        "Production path: hash table, multi-core LB, kernel UDP LB, ike-lb HA. "
        "See docs/DESIGN.md section 5."
    )
    pdf.add_page()

    pdf.text("6. Interop scope", bold=True)
    pdf.text(
        "Required: IKE structure, algorithms, IKE_SA_INIT/AUTH/CHILD flow, "
        "SPI stickiness. Recommended: NAT-T, DPD. Optional: MOBIKE, HA. "
        "Full tables in docs/INTEROP.md."
    )
    pdf.add_page()

    pdf.text("7. Real-world practicality", bold=True)
    pdf.text(
        "Lab proves SPI stickiness and IKE_SA_INIT via VIP; production needs "
        "identical iked configs, StrongSwan to VIP only, firewall 500/4500+ESP."
    )
    pdf.text("  Lab: symmetric LB relay. Prod: often direct backend IKE replies.")
    pdf.text("  Automated S-01: IKE_AUTH + CHILD via hub VIP (default 203.0.113.x)")
    pdf.text("  Manual: S-02 stickiness, S-03 config parity; S-04 NAT-T (10.10.x) open")
    pdf.text("  See docs/INTEROP_ALGORITHM_STATUS.md, INTEROP_NO_NAT")
    pdf.add_page()

    pdf.text("8. Session recording", bold=True)
    pdf.text("  docs/output/demo_recording.log / .html")
    pdf.text("  make record — Webex/video optional")
    pdf.text("  docs/PROMPTS.md — user prompts only")
    pdf.add_page()

    pdf.text("9. Prompt Log (All User Prompts)", bold=True)
    for num, title, body in PROMPTS:
        pdf.text(f"Prompt {num}: {title}", bold=True)
        pdf.text(body, size=10)
    pdf.add_page()

    pdf.text("10. References", bold=True)
    pdf.text("github.com/openiked/openiked-portable")
    pdf.text("github.com/strongswan/strongswan")
    pdf.text("RFC 7296 | docs/INTEROP.md (Required/Optional)")

    path = os.path.join(OUT_DIR, "IKEv2_LoadBalancer_Report.pdf")
    with open(path, "wb") as f:
        f.write(pdf.build())
    return path


def slide_xml(title, bullets):
    body = ""
    for i, b in enumerate(bullets):
        p_pr = '<a:buChar char="•"/>' if i == 0 else ""
        body += f"""      <a:p>
        <a:pPr lvl="0">{p_pr}</a:pPr>
        <a:r><a:rPr lang="en-US" sz="2000"/><a:t>{escape(b[:500])}</a:t></a:r>
      </a:p>"""
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
 xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <p:cSld><p:spTree>
    <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
    <p:grpSpPr/>
    <p:sp>
      <p:nvSpPr><p:cNvPr id="2" name="Title"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr/></p:nvSpPr>
      <p:spPr><a:xfrm><a:off x="457200" y="274638"/><a:ext cx="8229600" cy="1143000"/></a:xfrm></p:spPr>
      <p:txBody><a:bodyPr/><a:lstStyle/>
        <a:p><a:r><a:rPr lang="en-US" sz="3200" b="1"/><a:t>{escape(title)}</a:t></a:r></a:p>
      </p:txBody>
    </p:sp>
    <p:sp>
      <p:nvSpPr><p:cNvPr id="3" name="Content"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr/></p:nvSpPr>
      <p:spPr><a:xfrm><a:off x="457200" y="1600200"/><a:ext cx="8229600" cy="4525963"/></a:xfrm></p:spPr>
      <p:txBody><a:bodyPr/><a:lstStyle/>
{body}
      </p:txBody>
    </p:sp>
  </p:spTree></p:cSld>
  <p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>
</p:sld>"""


def build_pptx():
    slides = [
        ("IKEv2 Load Balancer", [
            "Hub-Spoke | OpenIKED + StrongSwan",
            datetime.now().strftime("%B %Y"),
        ]),
        ("Problem Statement", [
            "IKEv2 LB for large hub-spoke router network",
            "Hub: openiked-portable (iked)",
            "Spokes: StrongSwan client or server",
            "Hub VIP with SPI session stickiness",
        ]),
        ("Architecture & Flow", [
            "Hub-spoke: spokes -> VIP only",
            "IKE_SA_INIT: LB picks backend by Init SPI hash",
            "Later IKE: same backend (SPI sticky)",
            "ESP: kernel — not through LB",
            "See docs/FLOWS.md",
        ]),
        ("LLD Modules", [
            "ike_msg.c — IKE header & payloads",
            "ike_lb_session.c — config, SPI hash, sessions",
            "ike_lb_main.c — poll, forward, reply relay",
            "Makefile build-time limits",
        ]),
        ("Implementation Steps", [f"{t}: {d}" for t, d in STEPS]),
        ("Test Results", [
            "Unit tests: 31/31 PASS",
            "E2E + PCAP: run_e2e_tcpdump.sh",
            "Multi-session: 5/5 via LB",
            "S-01 automated PASS (StrongSwan); S-02–S-04 partial/manual",
        ]),
        ("Scalability", [
            "Horizontal: add iked backends; VIP unchanged",
            "65536 sessions, 32 backends (defaults)",
            "Bottlenecks: single-thread, linear lookup",
            "Production: hash table, multi-core, kernel LB, HA",
            "See docs/DESIGN.md section 5",
        ]),
        ("Interop: Required / Recommended / Optional", [
            "Required: IKE structure, algorithms, SPI stickiness, VIP",
            "Required for VPN: ESP, routing, firewall",
            "Recommended: NAT-T, DPD, backend health",
            "Optional: MOBIKE, LB HA — see docs/INTEROP.md",
        ]),
        ("Real-world practicality", [
            "Lab: IKE_SA_INIT + stickiness via demo client/LB",
            "Prod: StrongSwan + openiked; IKE_AUTH, ESP, certs",
            "Lab relay vs prod asymmetric IKE return",
            "S-04 NAT-T (10.10.x) before full go-live",
            "docs/PRACTICALITY.md + TEST_PLAN section 2",
        ]),
        ("Recording", [
            "demo_recording.log / .html (make record)",
            "Webex/video: user-provided",
            "docs/PROMPTS.md",
        ]),
        ("AI Usage in SDLC", [
            "Requirements → HLD/LLD → C code → tests",
            "Interop docs, build tuning, submission report",
        ]),
    ]
    for num, title, body in PROMPTS:
        slides.append((f"Prompt {num}: {title}", [body]))

    slides.append(("References", [
        "openiked-portable & strongswan (GitHub)",
        "RFC 7296 IKEv2",
        "docs/INTEROP.md — Required/Optional checklists",
        "docs/TEST_PLAN.md, docs/PRACTICALITY.md, docs/README.md",
    ]))

    path = os.path.join(OUT_DIR, "IKEv2_LoadBalancer_Report.pptx")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "[Content_Types].xml",
            """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
  <Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>
</Types>""",
        )
        z.writestr(
            "_rels/.rels",
            """<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
</Relationships>""",
        )
        slide_rels = ""
        slide_list = ""
        for i, (title, bullets) in enumerate(slides, 1):
            z.writestr(f"ppt/slides/slide{i}.xml", slide_xml(title, bullets))
            slide_list += f'<p:sldId id="{256+i}" r:id="rId{i}"/>'
            slide_rels += (
                f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" '
                f'Target="slides/slide{i}.xml"/>'
            )

        z.writestr(
            "ppt/_rels/presentation.xml.rels",
            f"""<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
{slide_rels}
</Relationships>""",
        )
        z.writestr(
            "ppt/presentation.xml",
            f"""<?xml version="1.0" encoding="UTF-8"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <p:sldIdLst>{slide_list}</p:sldIdLst>
  <p:sldSz cx="9144000" cy="6858000"/>
</p:presentation>""",
        )
    return path


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    pdf = build_pdf()
    ppt = build_pptx()
    print("Generated:")
    print(f"  PDF:  {pdf}")
    print(f"  PPTX: {ppt}")
    print(f"  MD:   {os.path.join(ROOT, 'docs', 'SUBMISSION_REPORT.md')}")


if __name__ == "__main__":
    main()
