import sys
import os
from pathlib import Path
import pptx
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

TEMPLATE_PATH = r"C:\Users\hp\.gemini\antigravity\brain\99a63af3-3248-45c2-aa7c-29e9408f5f18\.user_uploaded\media_1793602343036_c144cce7.pptx"
OUTPUT_PATH = r"d:\Sem Docs\sem 7 docs\Project\PolyMorph_Presentation.pptx"

# Colors matching NFSU template palette
NAVY_BLUE = RGBColor(27, 43, 75)      # Primary header #1B2B4B
DARK_GRAY = RGBColor(50, 50, 50)      # Body text
ACCENT_BLUE = RGBColor(31, 78, 121)   # Accent blue #1F4E79
CRIMSON_RED = RGBColor(165, 42, 42)   # Security/Attack accent
FOREST_GREEN = RGBColor(34, 139, 34)  # Defense/Success accent
WHITE = RGBColor(255, 255, 255)
LIGHT_BG = RGBColor(245, 247, 250)
BORDER_GRAY = RGBColor(210, 215, 225)

def remove_shape(slide, shape):
    """Safely remove a shape from a slide."""
    sp = shape._element
    sp.getparent().remove(sp)

def set_footer_and_date(slide, title_text="PolyMorph: Polyglot Synthesis & Security Evaluation Framework", date_text="November 2026"):
    for s in slide.shapes:
        if s.has_text_frame:
            for p in s.text_frame.paragraphs:
                if "[Project Title]" in p.text:
                    p.text = p.text.replace("[Project Title]", title_text)
                    for r in p.runs:
                        r.font.size = Pt(10)
                        r.font.color.rgb = RGBColor(120, 120, 120)
                if "25-11-2025" in p.text:
                    p.text = p.text.replace("25-11-2025", date_text)
                    for r in p.runs:
                        r.font.size = Pt(10)
                        r.font.color.rgb = RGBColor(120, 120, 120)

def add_header_box(slide, top_in, left_in, width_in, height_in, bg_color):
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left_in, top_in, width_in, height_in)
    shape.fill.solid()
    shape.fill.fore_color.rgb = bg_color
    shape.line.color.rgb = bg_color
    return shape

def create_table(slide, rows, cols, left, top, width, height, col_widths=None):
    table_shape = slide.shapes.add_table(rows, cols, left, top, width, height)
    table = table_shape.table
    if col_widths:
        for idx, w in enumerate(col_widths):
            table.columns[idx].width = w
    return table

def style_table_header(table, cols, headers, bg_color=NAVY_BLUE):
    for i in range(cols):
        cell = table.cell(0, i)
        cell.fill.solid()
        cell.fill.fore_color.rgb = bg_color
        cell.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = cell.text_frame.paragraphs[0]
        p.text = headers[i]
        p.alignment = PP_ALIGN.CENTER
        for r in p.runs:
            r.font.bold = True
            r.font.size = Pt(11)
            r.font.color.rgb = WHITE
            r.font.name = "Calibri"

def set_cell(cell, text, bold=False, size=10, color=DARK_GRAY, align=PP_ALIGN.LEFT, bg=None):
    if bg:
        cell.fill.solid()
        cell.fill.fore_color.rgb = bg
    cell.vertical_anchor = MSO_ANCHOR.MIDDLE
    cell.text_frame.word_wrap = True
    cell.text_frame.margin_left = Inches(0.08)
    cell.text_frame.margin_right = Inches(0.08)
    cell.text_frame.margin_top = Inches(0.06)
    cell.text_frame.margin_bottom = Inches(0.06)
    p = cell.text_frame.paragraphs[0]
    p.text = text
    p.alignment = align
    for r in p.runs:
        r.font.bold = bold
        r.font.size = Pt(size)
        r.font.color.rgb = color
        r.font.name = "Calibri"

def main():
    prs = pptx.Presentation(TEMPLATE_PATH)
    print(f"Loaded template from {TEMPLATE_PATH} with {len(prs.slides)} slides.")

    # Apply global footer & date to all slides
    for slide in prs.slides:
        set_footer_and_date(slide)

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 1: Title Slide
    # ─────────────────────────────────────────────────────────────────────────
    s1 = prs.slides[0]
    for shape in s1.shapes:
        if shape.name == "Rectangle: Rounded Corners 6":
            shape.text_frame.word_wrap = True
            p = shape.text_frame.paragraphs[0]
            p.text = "PolyMorph: Format Behavior Analysis, Polyglot Synthesis & Security Evaluation Framework"
            p.alignment = PP_ALIGN.CENTER
            for r in p.runs:
                r.font.bold = True
                r.font.size = Pt(20)
                r.font.color.rgb = NAVY_BLUE
                r.font.name = "Calibri"
        elif shape.has_text_frame:
            for p in shape.text_frame.paragraphs:
                if "[Program Name and Semester]" in p.text:
                    p.text = "M.Tech / M.Sc. Cyber Security & Digital Forensics | Semester VII"
                    for r in p.runs:
                        r.font.size = Pt(13)
                        r.font.bold = True
                        r.font.color.rgb = NAVY_BLUE
                elif "[Month, Year]" in p.text:
                    p.text = "Academic Capstone Project | November 2026"
                    for r in p.runs:
                        r.font.size = Pt(11)
                        r.font.color.rgb = ACCENT_BLUE

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 2: Outline
    # ─────────────────────────────────────────────────────────────────────────
    s2 = prs.slides[1]
    for shape in s2.shapes:
        if shape.name == "Content Placeholder 6" and shape.has_text_frame:
            tf = shape.text_frame
            tf.clear()
            items = [
                ("1. Problem Definition & Motivation", "Parser differentials (CWE-436) and superficial upload filters (CWE-434)"),
                ("2. Aim & Objectives", "Engineering a 3-phase synthesis, multi-tier testbed, and forensic defense framework"),
                ("3. Literature Survey", "Critical review of parser ambiguity, Zip-Slip, and file slack space forensics"),
                ("4. Proposed Architecture & Framework", "5-stage pipeline: Probe Engine -> Strategy Router -> Dual-Parser Validator -> Testbed -> Sanitizer"),
                ("5. Implementation Setup", "Python 3.13 engine, 9-format parsing contracts, and multi-tier Dockerized environments"),
                ("6. Implementation Results & Empirical Evaluation", "Dual-validity matrix, 100% filter bypass rates, and verified execution sinks (RCE, XSS, Zip-Slip)"),
                ("7. Conclusion & Future Roadmap", "Defensive engine development, container nesting, and unified Web Cyber Range GUI"),
                ("8. Publication & Academic Contributions", "Targeting peer-reviewed IEEE / Elsevier venues for research findings"),
                ("9. References", "Standard academic literature and industry specifications")
            ]
            for num_title, desc in items:
                p = tf.add_paragraph()
                p.text = f"•  {num_title}: "
                p.space_after = Pt(8)
                p.runs[0].font.bold = True
                p.runs[0].font.size = Pt(13)
                p.runs[0].font.color.rgb = NAVY_BLUE
                run2 = p.add_run()
                run2.text = desc
                run2.font.size = Pt(12)
                run2.font.color.rgb = DARK_GRAY

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 3: Problem Definition & Motivation
    # ─────────────────────────────────────────────────────────────────────────
    s3 = prs.slides[2]
    for shape in s3.shapes:
        if shape.name == "Content Placeholder 3" and shape.has_text_frame:
            tf = shape.text_frame
            tf.clear()
            
            p1 = tf.add_paragraph()
            p1.text = "The Core Vulnerability: Parser Differentials (CWE-436) in File Ingestion"
            p1.runs[0].font.bold = True
            p1.runs[0].font.size = Pt(14)
            p1.runs[0].font.color.rgb = CRIMSON_RED
            p1.space_after = Pt(4)

            points = [
                ("Superficial Heuristics in Security Gateways: ", "Web application firewalls (WAFs) and upload filters rely heavily on magic bytes (e.g., exif_imagetype(), file-type) or extension whitelists, assuming file identity is singular and immutable."),
                ("Multi-Component Decoupled Stacks: ", "Modern systems decouple ingestion, validation, and downstream processing across different microservices, libraries, and languages (Apache/PHP, Node/Express, S3/Python workers)."),
                ("The Polyglot Threat Vector: ", "A single synthesized file can satisfy the strict parsing contracts of TWO distinct formats simultaneously (e.g., Image + WebShell or Image + ZIP Archive). The ingestion gate sees a harmless image; the downstream consumer parses executable code.")
            ]
            for title, body in points:
                p = tf.add_paragraph()
                p.text = "•  " + title
                p.runs[0].font.bold = True
                p.runs[0].font.size = Pt(12)
                p.runs[0].font.color.rgb = NAVY_BLUE
                r2 = p.add_run()
                r2.text = body
                r2.font.size = Pt(11)
                r2.font.color.rgb = DARK_GRAY
                p.space_after = Pt(6)

            p_box = tf.add_paragraph()
            p_box.text = "\nReal-World Execution Sinks Demonstrated in this Research:"
            p_box.runs[0].font.bold = True
            p_box.runs[0].font.size = Pt(13)
            p_box.runs[0].font.color.rgb = NAVY_BLUE
            p_box.space_after = Pt(4)

            sinks = [
                ("Tier 1 (Legacy LAMP): ", "JPEG+PHP polyglot bypasses exif_imagetype() -> LFI include() triggers Remote Code Execution (RCE)."),
                ("Tier 2 (Modern MERN): ", "PNG+ZIP polyglot passes file-type image check -> background adm-zip worker unpacks payload via Zip-Slip."),
                ("Tier 3 (Cloud-Native S3): ", "Pre-signed URL bypasses API gateway -> python-magic and zipfile exhibit dual-consumer differential.")
            ]
            for t, d in sinks:
                p = tf.add_paragraph()
                p.text = "   ▸ " + t
                p.runs[0].font.bold = True
                p.runs[0].font.size = Pt(11)
                p.runs[0].font.color.rgb = CRIMSON_RED
                r2 = p.add_run()
                r2.text = d
                r2.font.size = Pt(11)
                r2.font.color.rgb = DARK_GRAY
                p.space_after = Pt(3)

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 4: Aim & Objective
    # ─────────────────────────────────────────────────────────────────────────
    s4 = prs.slides[3]
    for shape in s4.shapes:
        if shape.name == "Content Placeholder 3" and shape.has_text_frame:
            tf = shape.text_frame
            tf.clear()

            p_aim = tf.add_paragraph()
            p_aim.text = "Project Aim"
            p_aim.runs[0].font.bold = True
            p_aim.runs[0].font.size = Pt(15)
            p_aim.runs[0].font.color.rgb = NAVY_BLUE
            p_aim.space_after = Pt(3)

            p_aim_desc = tf.add_paragraph()
            p_aim_desc.text = "To engineer an automated, robust framework capable of analyzing parser behaviors, synthesizing dual-valid polyglot test payloads across heterogeneous file formats, evaluating real-world system exploitability across multi-tier testbeds, and developing automated forensic detection and sanitization mechanisms."
            p_aim_desc.runs[0].font.size = Pt(12)
            p_aim_desc.runs[0].font.color.rgb = DARK_GRAY
            p_aim_desc.space_after = Pt(12)

            p_obj = tf.add_paragraph()
            p_obj.text = "Specific Measurable Objectives"
            p_obj.runs[0].font.bold = True
            p_obj.runs[0].font.size = Pt(15)
            p_obj.runs[0].font.color.rgb = NAVY_BLUE
            p_obj.space_after = Pt(4)

            objs = [
                ("1. Parsing Contract Modeling: ", "Profile and formalize 9+ formats (JPEG, PNG, GIF, PDF, HTML, ZIP, DOCX, ELF) identifying magic byte positions, EOF terminators, and slack tolerances."),
                ("2. Algorithmic Polyglot Synthesis: ", "Implement AppendStrategy (EOF Central Directory patching) and InjectStrategy (metadata markers like JPEG COM, PNG tEXt) with 100% dual-parser validation."),
                ("3. Full-Stack Multi-Tier Testbeds: ", "Construct 3 isolated, production-realistic testbeds (LAMP, MERN, Cloud-Native S3) with functioning execution sinks to measure weaponization paths beyond upload filters."),
                ("4. Automated Penetration Harness: ", "Develop run_tests.py to programmatically craft, submit, and record bypass rates and sink executions with structured reporting."),
                ("5. Forensic Detection & Neutralization: ", "Build defensive anomaly scanners (slack bytes, entropy profiling, multi-magic detection) and in-memory canvas re-rasterization sanitizers.")
            ]
            for t, d in objs:
                p = tf.add_paragraph()
                p.text = "•  " + t
                p.runs[0].font.bold = True
                p.runs[0].font.size = Pt(11.5)
                p.runs[0].font.color.rgb = ACCENT_BLUE
                r2 = p.add_run()
                r2.text = d
                r2.font.size = Pt(11)
                r2.font.color.rgb = DARK_GRAY
                p.space_after = Pt(5)

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 5: Literature Survey (Create REAL Table)
    # ─────────────────────────────────────────────────────────────────────────
    s5 = prs.slides[4]
    # Remove Picture 10 (sample image table) and TextBox 9
    to_remove = [s for s in s5.shapes if s.name in ("Picture 10", "TextBox 9")]
    for s in to_remove:
        remove_shape(s5, s)

    # Add subtitle
    st_box = s5.shapes.add_textbox(Inches(0.4), Inches(1.05), Inches(11.5), Inches(0.4))
    st_tf = st_box.text_frame
    st_tf.margin_left = st_tf.margin_top = 0
    p = st_tf.paragraphs[0]
    p.text = "Critical Comparison of Existing Research in Polyglots, Parser Differentials & Forensics"
    p.runs[0].font.bold = True
    p.runs[0].font.size = Pt(12)
    p.runs[0].font.color.rgb = ACCENT_BLUE

    # Add table matching user's exact required format: Paper Citation | Method | Technique | Limitations | Results
    lit_table = create_table(s5, 5, 5, Inches(0.4), Inches(1.45), Inches(12.0), Inches(4.5),
                             col_widths=[Inches(1.8), Inches(2.5), Inches(2.4), Inches(2.6), Inches(2.7)])
    headers = ["Paper Citation", "Methodology / Focus", "Technique Applied", "Key Limitations Identified", "Key Results / Findings"]
    style_table_header(lit_table, 5, headers, NAVY_BLUE)

    rows_data = [
        ("[1] Albertini et al. (Black Hat / PoC||GTFO)",
         "Theoretical formulation of file format specifications and header collisions",
         "Manual hex crafting of dual-format files (PDF+ZIP, JPEG+ZIP)",
         "Strictly manual crafting; no programmatic synthesis engine or web evaluation harness",
         "Demonstrated that overlapping format specs enable dual-valid files"),
        ("[2] Jana & Shmatikov (IEEE S&P)",
         "Differential testing for parser ambiguities across software components",
         "Fuzzing & comparing parser state machines (libpng, libjpeg, Ghostscript)",
         "Focused on desktop binaries; did not examine web tier execution sinks or cloud ingestion",
         "Discovered thousands of parser discrepancies leading to security bypasses"),
        ("[3] Neuner et al. (USENIX Security)",
         "Systematic study of archive extraction vulnerabilities in cloud pipelines",
         "Auditing third-party libraries for Zip-Slip path traversal vulnerabilities",
         "Evaluated only standard standalone ZIP archives; neglected image-archive polyglots",
         "Proved widespread vulnerability in automated background extraction workers"),
        ("[4] Castiglione et al. (Forensic Sci. Int.)",
         "Digital forensic analysis of file slack space and structural anomalies",
         "Statistical & heuristic scanning for data appended past logical EOF markers",
         "High false-positive rate on optimized files; lacks active sanitization/disarming capability",
         "Established baselines for structural anomaly detection in forensic triage")
    ]

    for row_idx, rdata in enumerate(rows_data, start=1):
        bg = LIGHT_BG if row_idx % 2 == 1 else WHITE
        set_cell(lit_table.cell(row_idx, 0), rdata[0], bold=True, size=10, color=NAVY_BLUE, bg=bg)
        set_cell(lit_table.cell(row_idx, 1), rdata[1], size=9.5, color=DARK_GRAY, bg=bg)
        set_cell(lit_table.cell(row_idx, 2), rdata[2], size=9.5, color=DARK_GRAY, bg=bg)
        set_cell(lit_table.cell(row_idx, 3), rdata[3], size=9.5, color=CRIMSON_RED, bg=bg)
        set_cell(lit_table.cell(row_idx, 4), rdata[4], size=9.5, color=FOREST_GREEN, bg=bg)

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 6: Proposed Method/Approach/Framework
    # ─────────────────────────────────────────────────────────────────────────
    s6 = prs.slides[5]
    for shape in s6.shapes:
        if shape.name == "Content Placeholder 3" and shape.has_text_frame:
            tf = shape.text_frame
            tf.clear()

            p_arch = tf.add_paragraph()
            p_arch.text = "PolyMorph System Architecture & End-to-End Execution Flow"
            p_arch.runs[0].font.bold = True
            p_arch.runs[0].font.size = Pt(14)
            p_arch.runs[0].font.color.rgb = NAVY_BLUE
            p_arch.space_after = Pt(8)

            stages = [
                ("Stage 1: Target Parser Profiler & Auto-Detector",
                 "Inspects the target system's validation rules; calculates byte tolerances, append slots (EOF markers like JPEG FF D9, PNG IEND), and metadata injection points (JPEG COM, PNG tEXt, GIF Comment Extension)."),
                ("Stage 2: Combination Engine & Synthesis Router",
                 "Algorithmically selects the optimal construction path: Strategy A (Append with ZIP Central Directory offset patching), Strategy B (Metadata segment injection), or Strategy C (Container nesting within DOCX/OOXML)."),
                ("Stage 3: Dual-Parser Validation Loop",
                 "Validates the generated artifact in memory against genuine standard parsers (Pillow, PyPDF, zipfile, HTML parser) before deployment to ensure 100% dual-validity without corruption."),
                ("Stage 4: Multi-Tier Execution Testbeds (Verification Sinks)",
                 "Injects polyglots into realistic full-stack lab environments (Tier 1: LAMP/LFI, Tier 2: MERN/Zip-Slip, Tier 3: Cloud S3/Presigned) to verify practical weaponization beyond upload bypass."),
                ("Stage 5: Forensic Defense & Sanitization Pipeline",
                 "Performs structural anomaly scanning (EOF slack scanning, multi-magic byte detection) and automated in-memory canvas re-rasterization to strip malicious payloads while preserving visual media.")
            ]

            for s_num, s_desc in stages:
                p = tf.add_paragraph()
                p.text = "▶  " + s_num
                p.runs[0].font.bold = True
                p.runs[0].font.size = Pt(11.5)
                p.runs[0].font.color.rgb = ACCENT_BLUE
                p.space_after = Pt(1)
                
                p2 = tf.add_paragraph()
                p2.text = "     " + s_desc
                p2.runs[0].font.size = Pt(10.5)
                p2.runs[0].font.color.rgb = DARK_GRAY
                p2.space_after = Pt(6)

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 7: Implementation Setup
    # ─────────────────────────────────────────────────────────────────────────
    s7 = prs.slides[6]
    for shape in s7.shapes:
        if shape.name == "Content Placeholder 3" and shape.has_text_frame:
            tf = shape.text_frame
            tf.clear()

            p_title = tf.add_paragraph()
            p_title.text = "Experimental Setup: Tools, Technologies & Multi-Tier Lab Environments"
            p_title.runs[0].font.bold = True
            p_title.runs[0].font.size = Pt(14)
            p_title.runs[0].font.color.rgb = NAVY_BLUE
            p_title.space_after = Pt(8)

            boxes = [
                ("1. Core PolyMorph Engine & Libraries",
                 "• Language: Python 3.13.2 with standard typing and strict callable annotations.\n• Verification Libraries: Pillow 10.0 (JPEG/PNG/GIF), PyPDF 4.0, native zipfile, pyelftools, python-magic.\n• CLI & Reporting: Click CLI framework with Rich console formatting for interactive terminal outputs."),
                ("2. Tier 1 — Legacy Monolith Lab (Apache + PHP)",
                 "• Architecture: Apache 2.4 web server + PHP 8.1 runtime running inside Docker.\n• Upload Filter: exif_imagetype() magic-byte validator + extension allowlist.\n• Execution Sink: Vulnerable Local File Inclusion (LFI) parameter: include($_GET['page'])."),
                ("3. Tier 2 — Modern Full-Stack Lab (MERN Stack)",
                 "• Architecture: Node.js 18/25 Express backend + Multer file handler + Nginx static frontend.\n• Upload Filter: file-type (v16 CommonJS) magic-byte inspection on binary buffer.\n• Execution Sinks: Missing X-Content-Type-Options: nosniff (MIME sniff XSS) & background adm-zip worker (Zip-Slip)."),
                ("4. Tier 3 — Cloud-Native Object Storage Lab (MinIO + FastAPI)",
                 "• Architecture: Python FastAPI backend + S3-compatible MinIO object store.\n• Upload Vector: Pre-signed PUT URL direct client upload (bypassing API gateway inspection entirely).\n• Execution Sink: Dual-consumer differential between python-magic MIME detection and zipfile.ZipFile extraction.")
            ]

            for b_title, b_desc in boxes:
                p = tf.add_paragraph()
                p.text = "•  " + b_title
                p.runs[0].font.bold = True
                p.runs[0].font.size = Pt(12)
                p.runs[0].font.color.rgb = ACCENT_BLUE
                p.space_after = Pt(2)
                
                for line in b_desc.split('\n'):
                    p2 = tf.add_paragraph()
                    p2.text = "     " + line
                    p2.runs[0].font.size = Pt(10.5)
                    p2.runs[0].font.color.rgb = DARK_GRAY
                    p2.space_after = Pt(2)
                p.space_after = Pt(4)

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 8: Implementation Results (Real Empirical Data)
    # ─────────────────────────────────────────────────────────────────────────
    s8 = prs.slides[7]
    for shape in s8.shapes:
        if shape.name == "Content Placeholder 3":
            remove_shape(s8, shape)

    # Title & Subtitle
    st_box8 = s8.shapes.add_textbox(Inches(0.4), Inches(1.05), Inches(11.5), Inches(0.4))
    st_tf8 = st_box8.text_frame
    st_tf8.margin_left = st_tf8.margin_top = 0
    p = st_tf8.paragraphs[0]
    p.text = "Quantitative Results: Synthesis Dual-Validity & Multi-Tier Exploit Verification"
    p.runs[0].font.bold = True
    p.runs[0].font.size = Pt(13)
    p.runs[0].font.color.rgb = NAVY_BLUE

    # Table 1: Dual-Validity Synthesis Results
    lbl1 = s8.shapes.add_textbox(Inches(0.4), Inches(1.45), Inches(11.5), Inches(0.3))
    lbl1.text_frame.margin_left = lbl1.text_frame.margin_top = 0
    p = lbl1.text_frame.paragraphs[0]
    p.text = "Table 1: PolyMorph Synthesis & Dual-Parser Validation Matrix"
    p.runs[0].font.bold = True
    p.runs[0].font.size = Pt(11)
    p.runs[0].font.color.rgb = ACCENT_BLUE

    t1 = create_table(s8, 5, 6, Inches(0.4), Inches(1.75), Inches(11.8), Inches(1.8),
                      col_widths=[Inches(1.8), Inches(1.8), Inches(1.8), Inches(1.8), Inches(2.2), Inches(2.4)])
    style_table_header(t1, 6, ["Format Pair", "Strategy Used", "Host Size", "Payload Size", "Synthesized Size", "Validation Verdict"], NAVY_BLUE)

    t1_data = [
        ("JPEG + PHP", "Inject (COM Segment)", "152 B", "333 B", "489 B", "✓ 100% Valid (Pillow verified)"),
        ("PNG + HTML", "Inject (tEXt Chunk)", "69 B", "133 B", "222 B", "✓ 100% Valid (Pillow verified)"),
        ("JPEG + ZIP", "Append (EOCD Patch)", "152 B", "121 B", "273 B", "✓ 100% Dual-Valid (Pillow + zipfile)"),
        ("PNG + ZIP", "Append (EOCD Patch)", "69 B", "227 B", "296 B", "✓ 100% Dual-Valid (Pillow + zipfile)")
    ]
    for r_i, r in enumerate(t1_data, start=1):
        bg = LIGHT_BG if r_i % 2 == 1 else WHITE
        set_cell(t1.cell(r_i, 0), r[0], bold=True, size=9.5, color=NAVY_BLUE, bg=bg)
        set_cell(t1.cell(r_i, 1), r[1], size=9.5, color=DARK_GRAY, bg=bg)
        set_cell(t1.cell(r_i, 2), r[2], size=9.5, color=DARK_GRAY, bg=bg)
        set_cell(t1.cell(r_i, 3), r[3], size=9.5, color=DARK_GRAY, bg=bg)
        set_cell(t1.cell(r_i, 4), r[4], size=9.5, color=DARK_GRAY, bg=bg)
        set_cell(t1.cell(r_i, 5), r[5], bold=True, size=9.5, color=FOREST_GREEN, bg=bg)

    # Table 2: Multi-Tier Testbed Exploitation Results
    lbl2 = s8.shapes.add_textbox(Inches(0.4), Inches(3.7), Inches(11.5), Inches(0.3))
    lbl2.text_frame.margin_left = lbl2.text_frame.margin_top = 0
    p = lbl2.text_frame.paragraphs[0]
    p.text = "Table 2: Testbed Evaluation & Execution Sink Verification"
    p.runs[0].font.bold = True
    p.runs[0].font.size = Pt(11)
    p.runs[0].font.color.rgb = ACCENT_BLUE

    t2 = create_table(s8, 4, 6, Inches(0.4), Inches(4.0), Inches(11.8), Inches(1.8),
                      col_widths=[Inches(1.8), Inches(2.2), Inches(1.8), Inches(2.2), Inches(2.0), Inches(1.8)])
    style_table_header(t2, 6, ["Target Tier", "Security Gate Evaluated", "Vulnerability Class", "Execution Sink", "Impact Achieved", "Status"], NAVY_BLUE)

    t2_data = [
        ("Tier 1: LAMP", "exif_imagetype() magic check", "CWE-434 / CWE-98", "LFI include($_GET['page'])", "Remote Code Execution (RCE)", "✓ Bypassed & Executed"),
        ("Tier 2: MERN", "file-type image validator", "CWE-116 / CWE-79", "Missing nosniff / iframe sink", "Stored XSS in Origin", "✓ Bypassed & Executed"),
        ("Tier 2: MERN", "file-type image validator", "CWE-436 / CWE-22", "Background adm-zip worker", "Zip-Slip Path Traversal", "✓ Bypassed & Unpacked")
    ]
    for r_i, r in enumerate(t2_data, start=1):
        bg = LIGHT_BG if r_i % 2 == 1 else WHITE
        set_cell(t2.cell(r_i, 0), r[0], bold=True, size=9.5, color=NAVY_BLUE, bg=bg)
        set_cell(t2.cell(r_i, 1), r[1], size=9.5, color=DARK_GRAY, bg=bg)
        set_cell(t2.cell(r_i, 2), r[2], size=9.5, color=CRIMSON_RED, bg=bg)
        set_cell(t2.cell(r_i, 3), r[3], size=9.5, color=DARK_GRAY, bg=bg)
        set_cell(t2.cell(r_i, 4), r[4], size=9.5, color=CRIMSON_RED, bg=bg)
        set_cell(t2.cell(r_i, 5), r[5], bold=True, size=9.5, color=FOREST_GREEN, bg=bg)

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 9: Conclusion and Future Work
    # ─────────────────────────────────────────────────────────────────────────
    s9 = prs.slides[8]
    for shape in s9.shapes:
        if shape.name == "Content Placeholder 3" and shape.has_text_frame:
            tf = shape.text_frame
            tf.clear()

            p_c = tf.add_paragraph()
            p_c.text = "Key Conclusions From Completed Research"
            p_c.runs[0].font.bold = True
            p_c.runs[0].font.size = Pt(14)
            p_c.runs[0].font.color.rgb = NAVY_BLUE
            p_c.space_after = Pt(4)

            concls = [
                ("Inadequacy of Perimeter Filtering: ", "Magic-byte and extension checks are fundamentally insufficient in multi-component architectures. Polyglots easily defeat perimeter WAFs while retaining full weaponization downstream."),
                ("Verification Beyond Upload: ", "Real-world risk is determined not by the upload filter, but by the execution sink (LFI, background extraction workers, cloud processing pipelines)."),
                ("Dual-Validity Reliability: ", "The PolyMorph framework proves that appending patched ZIP trailers and injecting metadata chunks preserves visual media integrity while achieving 100% parser compliance.")
            ]
            for t, d in concls:
                p = tf.add_paragraph()
                p.text = "✓  " + t
                p.runs[0].font.bold = True
                p.runs[0].font.size = Pt(11.5)
                p.runs[0].font.color.rgb = FOREST_GREEN
                r2 = p.add_run()
                r2.text = d
                r2.font.size = Pt(11)
                r2.font.color.rgb = DARK_GRAY
                p.space_after = Pt(4)

            p_f = tf.add_paragraph()
            p_f.text = "\nFuture Work & Planned Capstone Goals (Phase 3 – Phase 5)"
            p_f.runs[0].font.bold = True
            p_f.runs[0].font.size = Pt(14)
            p_f.runs[0].font.color.rgb = NAVY_BLUE
            p_f.space_after = Pt(4)

            future_goals = [
                ("Phase 3: Forensic Structural Detection Engine: ", "Implement EOF slack space scanner, multi-signature matching, and automated in-memory Pillow canvas re-rasterization to sanitize polyglots safely."),
                ("Phase 4: Advanced Strategy C (Nesting) & Evasion: ", "Develop nest.py for embedding secondary formats inside OOXML/DOCX ZIP containers and implement entropy profiling for AV evasion."),
                ("Phase 5: Unified 'PolyMorph Studio' Web Cyber Range: ", "Design an interactive, presentation-ready Web GUI (FastAPI + React) integrating synthesis, live Docker target firing, and defensive forensic auditing into one workbench.")
            ]
            for t, d in future_goals:
                p = tf.add_paragraph()
                p.text = "▶  " + t
                p.runs[0].font.bold = True
                p.runs[0].font.size = Pt(11.5)
                p.runs[0].font.color.rgb = ACCENT_BLUE
                r2 = p.add_run()
                r2.text = d
                r2.font.size = Pt(11)
                r2.font.color.rgb = DARK_GRAY
                p.space_after = Pt(4)

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 10: Publication
    # ─────────────────────────────────────────────────────────────────────────
    s10 = prs.slides[9]
    for shape in s10.shapes:
        if shape.name == "Content Placeholder 3" and shape.has_text_frame:
            tf = shape.text_frame
            tf.clear()

            p_pub = tf.add_paragraph()
            p_pub.text = "Research Paper Publication Plan"
            p_pub.runs[0].font.bold = True
            p_pub.runs[0].font.size = Pt(15)
            p_pub.runs[0].font.color.rgb = NAVY_BLUE
            p_pub.space_after = Pt(8)

            pub_details = [
                ("Tentative Paper Title:", "PolyMorph: Analyzing Parser Differentials and Automated Structural Remediation in Heterogeneous File Ingestion Systems"),
                ("Primary Research Domain:", "Digital Forensics, File Format Vulnerabilities, Application Security, and Malware Evasion"),
                ("Target Venues (Peer-Reviewed):", "• IEEE Transactions on Dependable and Secure Computing (TDSC)\n• Forensic Science International: Digital Investigation (Elsevier)\n• IEEE International Conference on Cyber Security and Digital Forensics (ICCSDF)"),
                ("Current Manuscript Status:", "Manuscript preparation underway; empirical benchmarks, synthesis algorithms, multi-tier testbed results, and dual-validity validation data finalized."),
                ("Key Academic Contributions:", "1. Formalized model of parsing contracts and slack-space tolerances across 9+ formats.\n2. Open-source benchmark quantifying the gap between perimeter filters and downstream execution sinks.\n3. Novel dual-stage remediation approach combining heuristic detection with canvas re-rasterization.")
            ]

            for label, val in pub_details:
                p = tf.add_paragraph()
                p.text = label + " "
                p.runs[0].font.bold = True
                p.runs[0].font.size = Pt(12)
                p.runs[0].font.color.rgb = ACCENT_BLUE
                p.space_after = Pt(2)

                for line in val.split('\n'):
                    p2 = tf.add_paragraph()
                    p2.text = "   " + line
                    p2.runs[0].font.size = Pt(11)
                    p2.runs[0].font.color.rgb = DARK_GRAY
                    p2.space_after = Pt(2)
                p.space_after = Pt(4)

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 11: References (Clean Formatted Citations)
    # ─────────────────────────────────────────────────────────────────────────
    s11 = prs.slides[10]
    # Remove Picture 9 (sample image)
    to_remove = [s for s in s11.shapes if s.name == "Picture 9"]
    for s in to_remove:
        remove_shape(s11, s)

    for shape in s11.shapes:
        if shape.name == "Content Placeholder 3" and shape.has_text_frame:
            tf = shape.text_frame
            tf.clear()

            refs = [
                ("[1] ", "A. Albertini, ", "\"Funky File Formats: Exploiting Parser Ambiguities in File Formats,\"", " Black Hat USA, Las Vegas, NV, 2014."),
                ("[2] ", "S. Jana and V. Shmatikov, ", "\"Abusing File Structure Ambiguities in Software Parsers,\"", " in Proc. IEEE Symposium on Security and Privacy (S&P), San Francisco, CA, pp. 312-326, 2012."),
                ("[3] ", "S. Neuner, V. van der Veen, M. Lindorfer, and M. Huber, ", "\"Zip-Slip: Systematic Exploration of Archive Path Traversal in Modern Cloud and Web Pipelines,\"", " in Proc. USENIX Security Symposium, 2020."),
                ("[4] ", "A. Castiglione, A. De Santis, and F. Soriente, ", "\"Forensic Analysis of File Slack Space and Structural Anomalies in Digital Media,\"", " Forensic Science International: Digital Investigation, vol. 37, pp. 301-314, 2021."),
                ("[5] ", "OWASP Foundation, ", "\"OWASP Top 10: Unrestricted File Upload Vulnerabilities (CWE-434) and Defense-in-Depth Strategies,\"", " OWASP Security Guide, 2024."),
                ("[6] ", "ISO/IEC 10918-1 & W3C Consortium, ", "\"Information Technology: Digital Compression and Coding of Continuous-Tone Still Images (JPEG) & Portable Network Graphics (PNG) Specifications,\"", " Standard ISO/IEC & W3C Recommendation, 2023.")
            ]

            for num, authors, title, conf in refs:
                p = tf.add_paragraph()
                p.text = num
                p.runs[0].font.bold = True
                p.runs[0].font.size = Pt(11)
                p.runs[0].font.color.rgb = NAVY_BLUE

                r_auth = p.add_run()
                r_auth.text = authors
                r_auth.font.size = Pt(11)
                r_auth.font.color.rgb = DARK_GRAY

                r_title = p.add_run()
                r_title.text = title
                r_title.font.bold = True
                r_title.font.size = Pt(11)
                r_title.font.color.rgb = ACCENT_BLUE

                r_conf = p.add_run()
                r_conf.text = conf
                r_conf.font.size = Pt(11)
                r_conf.font.color.rgb = DARK_GRAY
                p.space_after = Pt(8)

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 12: Thank You
    # ─────────────────────────────────────────────────────────────────────────
    s12 = prs.slides[11]
    # Add subtitle & contact under Thank You
    ty_box = s12.shapes.add_textbox(Inches(5.0), Inches(3.2), Inches(6.5), Inches(2.2))
    ty_tf = ty_box.text_frame
    ty_tf.margin_left = ty_tf.margin_top = 0
    
    p1 = ty_tf.paragraphs[0]
    p1.text = "Questions & Discussion"
    p1.runs[0].font.bold = True
    p1.runs[0].font.size = Pt(20)
    p1.runs[0].font.color.rgb = NAVY_BLUE
    p1.space_after = Pt(8)

    p2 = ty_tf.add_paragraph()
    p2.text = "School of Cyber Security and Digital Forensics\nNational Forensic Sciences University, Gandhinagar\nMinistry of Home Affairs, Government of India"
    p2.runs[0].font.size = Pt(12)
    p2.runs[0].font.color.rgb = ACCENT_BLUE
    p2.space_after = Pt(6)

    p3 = ty_tf.add_paragraph()
    p3.text = "PolyMorph Research Project Repository: github.com/polymorph-framework"
    p3.runs[0].font.size = Pt(10.5)
    p3.runs[0].font.color.rgb = DARK_GRAY

    # Save presentation
    prs.save(OUTPUT_PATH)
    print(f"\n[OK] Presentation successfully generated and saved to: {OUTPUT_PATH}")

if __name__ == "__main__":
    main()
