"""Professional PDF report generation and sanitized CSV export without external dependencies."""
import csv
import io
from datetime import datetime, timezone

def sanitize_csv_cell(value):
    """
    Prevent Spreadsheet Formula Injection (CSV / Excel macro execution).
    Prefix cells starting with =, +, -, @, \t, or \r with a single quote.
    """
    if value is None:
        return ''
    s = str(value)
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + s
    return s

def export_batch_csv(items):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'URL', 'Host', 'Risk Score', 'Verdict', 'Graph Score',
        'Lexical Score', 'Limited Support', 'Signals Count', 'Top Signal'
    ])
    for item in items:
        signals = item.get('signals', [])
        top_sig = signals[0]['signal'] if signals else 'None'
        writer.writerow([
            sanitize_csv_cell(item.get('url')),
            sanitize_csv_cell(item.get('host')),
            item.get('risk_score'),
            sanitize_csv_cell(item.get('verdict')),
            item.get('graph_score'),
            item.get('lexical_score'),
            'Yes' if item.get('limited_support') else 'No',
            len(signals),
            sanitize_csv_cell(top_sig)
        ])
    return output.getvalue().encode('utf-8-sig')


class SimplePDF:
    """
    Pure Python vector PDF 1.4 document builder.
    Outputs standard compliant A4 PDF files with text, vector cards, and tables.
    """
    def __init__(self, title="PhishGraph Security Report"):
        self.title = title
        self.pages = []
        self.current_stream = []
        self.width = 595.28   # A4 width in pt
        self.height = 841.89  # A4 height in pt

    def new_page(self):
        if self.current_stream:
            self.pages.append("".join(self.current_stream))
            self.current_stream = []

    def rect(self, x, y, w, h, fill_rgb=None, stroke_rgb=None, line_width=1):
        s = "q "
        if stroke_rgb:
            r, g, b = stroke_rgb
            s += f"{r:.3f} {g:.3f} {b:.3f} RG {line_width:.2f} w "
        if fill_rgb:
            r, g, b = fill_rgb
            s += f"{r:.3f} {g:.3f} {b:.3f} rg "
        s += f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re "
        if fill_rgb and stroke_rgb:
            s += "B Q\n"
        elif fill_rgb:
            s += "f Q\n"
        else:
            s += "S Q\n"
        self.current_stream.append(s)

    def text(self, text, x, y, font="F1", size=10, rgb=(0.1, 0.1, 0.1)):
        # Escape PDF special chars
        clean = (str(text).replace('\\', '\\\\')
                          .replace('(', '\\(')
                          .replace(')', '\\)'))
        r, g, b = rgb
        cmd = f"BT /{font} {size} Tf {r:.3f} {g:.3f} {b:.3f} rg {x:.2f} {y:.2f} Td ({clean}) Tj ET\n"
        self.current_stream.append(cmd)

    def build(self):
        if self.current_stream:
            self.pages.append("".join(self.current_stream))
            self.current_stream = []

        if not self.pages:
            self.pages.append("")

        objects = []
        
        def add_object(content):
            objects.append(content)
            return len(objects)

        # 1: Catalog
        cat_id = add_object("<< /Type /Catalog /Pages 2 0 R >>")
        
        # We will populate Pages (id 2) after creating Page objects
        page_ids = []
        for i, stream_text in enumerate(self.pages):
            stream_bytes = stream_text.encode('latin1', errors='replace')
            s_len = len(stream_bytes)
            # Content object
            c_id = add_object(f"<< /Length {s_len} >>\nstream\n{stream_text}\nendstream")
            # Page object
            p_id = add_object(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595.28 841.89] "
                              f"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> "
                              f"/F2 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >> "
                              f"/F3 << /Type /Font /Subtype /Type1 /BaseFont /Courier >> >> >> "
                              f"/Contents {c_id} 0 R >>")
            page_ids.append(p_id)

        # 2: Pages container
        kids = " ".join(f"{pid} 0 R" for pid in page_ids)
        pages_content = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>"
        objects.insert(1, pages_content) # Position 2 in 1-based indexing

        # Re-index objects correctly
        out = bytearray()
        out.extend(b"%PDF-1.4\n")
        offsets = []

        for i, obj in enumerate(objects, 1):
            offsets.append(len(out))
            out.extend(f"{i} 0 obj\n{obj}\nendobj\n".encode('latin1'))

        xref_pos = len(out)
        out.extend(f"xref\n0 {len(objects) + 1}\n".encode('latin1'))
        out.extend(b"0000000000 65535 f \n")
        for offset in offsets:
            out.extend(f"{offset:010d} 00000 n \n".encode('latin1'))

        trailer = f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF"
        out.extend(trailer.encode('latin1'))
        return bytes(out)


def generate_single_pdf_report(res):
    """
    Generate professional security research evaluation report for a single URL.
    Suspicious URLs are formatted cleanly as sanitized non-clickable text.
    """
    pdf = SimplePDF(f"PhishGraph Analysis - {res.get('host')}")
    
    # Header Bar
    pdf.rect(0, 780, 595.28, 62, fill_rgb=(0.06, 0.09, 0.16))
    pdf.text("PHISHGRAPH · SECURITY RESEARCH LAB", 40, 818, font="F2", size=13, rgb=(0.14, 0.75, 0.85))
    pdf.text("Graph ML & Sugeno Fuzzy Logic Phishing Threat Assessment", 40, 802, font="F1", size=8.5, rgb=(0.8, 0.85, 0.9))

    # Meta banner
    pdf.rect(40, 725, 515, 42, fill_rgb=(0.95, 0.96, 0.98), stroke_rgb=(0.85, 0.88, 0.92))
    pdf.text(f"Analysis Host: {res.get('host')[:55]}", 50, 749, font="F2", size=11, rgb=(0.08, 0.12, 0.2))
    dt_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    pdf.text(f"Generated: {dt_str}  |  Model: {res.get('model_version', 'v1-demo')} ({'Synthetic Demo' if res.get('demo') else 'Production Labeled'})", 50, 735, font="F1", size=8, rgb=(0.4, 0.45, 0.5))

    # Risk Verdict Card
    verdict_str = res.get('verdict', 'Unknown')
    risk_score = res.get('risk_score', 0)
    
    if verdict_str == 'High risk':
        card_bg = (0.99, 0.93, 0.93)
        card_border = (0.9, 0.3, 0.3)
        badge_rgb = (0.8, 0.1, 0.1)
    elif verdict_str == 'Review needed':
        card_bg = (0.99, 0.96, 0.9)
        card_border = (0.9, 0.6, 0.2)
        badge_rgb = (0.7, 0.4, 0.0)
    else:
        card_bg = (0.93, 0.98, 0.94)
        card_border = (0.3, 0.7, 0.4)
        badge_rgb = (0.1, 0.55, 0.25)

    pdf.rect(40, 615, 515, 95, fill_rgb=card_bg, stroke_rgb=card_border, line_width=1.5)
    pdf.text("PRIMARY VERDICT & COMBINED RISK INDEX", 55, 692, font="F2", size=9, rgb=(0.3, 0.35, 0.4))
    pdf.text(f"{verdict_str.upper()}", 55, 665, font="F2", size=20, rgb=badge_rgb)
    pdf.text(f"Composite Risk Score: {risk_score:.1f} / 100", 55, 645, font="F2", size=11, rgb=(0.1, 0.1, 0.1))
    
    if res.get('limited_support'):
        pdf.text("WARNING: Limited Model Support (Sample is far from training distribution).", 55, 627, font="F2", size=8.5, rgb=(0.85, 0.2, 0.2))
    else:
        pdf.text("Evaluation derived from RBF manifold similarity and 9 Sugeno fuzzy inference rules.", 55, 627, font="F1", size=8, rgb=(0.4, 0.45, 0.5))

    # Tri-Evidence Breakdown Table
    pdf.rect(40, 505, 515, 95, fill_rgb=(1, 1, 1), stroke_rgb=(0.85, 0.88, 0.92))
    pdf.text("EVIDENCE SYNTHESIS BREAKDOWN", 50, 582, font="F2", size=9.5, rgb=(0.1, 0.15, 0.25))
    
    # Sub-columns
    g_score = res.get('graph_score', 0)
    l_score = res.get('lexical_score', 0)
    
    # Col 1: Graph ML
    pdf.rect(50, 520, 155, 50, fill_rgb=(0.96, 0.98, 1.0), stroke_rgb=(0.8, 0.88, 0.96))
    pdf.text("Graph ML Proximity", 58, 555, font="F2", size=8.5, rgb=(0.1, 0.3, 0.6))
    pdf.text(f"{g_score:.1f} %", 58, 535, font="F2", size=14, rgb=(0.1, 0.4, 0.7))
    pdf.text("LabelSpreading RBF", 58, 525, font="F1", size=7, rgb=(0.4, 0.5, 0.6))

    # Col 2: Lexical Heuristics
    pdf.rect(220, 520, 155, 50, fill_rgb=(0.98, 0.96, 1.0), stroke_rgb=(0.88, 0.82, 0.96))
    pdf.text("Lexical Warning Index", 228, 555, font="F2", size=8.5, rgb=(0.4, 0.2, 0.6))
    pdf.text(f"{l_score:.1f} %", 228, 535, font="F2", size=14, rgb=(0.45, 0.2, 0.65))
    pdf.text("15 Structural Heuristics", 228, 525, font="F1", size=7, rgb=(0.5, 0.4, 0.6))

    # Col 3: Sugeno Defuzzified
    pdf.rect(390, 520, 155, 50, fill_rgb=(0.95, 0.98, 0.96), stroke_rgb=(0.8, 0.92, 0.85))
    pdf.text("Sugeno Fuzzy Synthesis", 398, 555, font="F2", size=8.5, rgb=(0.1, 0.5, 0.3))
    pdf.text(f"{risk_score:.1f} %", 398, 535, font="F2", size=14, rgb=(0.1, 0.55, 0.3))
    pdf.text("Weighted Consequent", 398, 525, font="F1", size=7, rgb=(0.3, 0.5, 0.4))

    # Warning Signals Box
    pdf.rect(40, 375, 515, 115, fill_rgb=(1, 1, 1), stroke_rgb=(0.85, 0.88, 0.92))
    pdf.text("OBSERVED STRUCTURAL SIGNALS & HEURISTIC WEIGHTS", 50, 472, font="F2", size=9.5, rgb=(0.1, 0.15, 0.25))
    signals = res.get('signals', [])
    if signals:
        y_pos = 452
        for s in signals[:5]:
            pdf.text(f"- {s['signal']}", 55, y_pos, font="F2", size=8.5, rgb=(0.2, 0.25, 0.3))
            pdf.text(f"+{s.get('weight', 0):.2f}", 480, y_pos, font="F3", size=8.5, rgb=(0.6, 0.2, 0.2))
            y_pos -= 16
    else:
        pdf.text("No high-risk lexical indicators flagged. (Absence of indicators does NOT establish safety).", 55, 440, font="F1", size=8.5, rgb=(0.4, 0.45, 0.5))

    # Nearest Graph Neighbors
    pdf.rect(40, 215, 515, 145, fill_rgb=(1, 1, 1), stroke_rgb=(0.85, 0.88, 0.92))
    pdf.text("LOCAL GRAPH NEIGHBORHOOD (RBF Similarity)", 50, 342, font="F2", size=9.5, rgb=(0.1, 0.15, 0.25))
    pdf.text("Host", 55, 325, font="F2", size=8, rgb=(0.4, 0.45, 0.5))
    pdf.text("RBF Sim", 260, 325, font="F2", size=8, rgb=(0.4, 0.45, 0.5))
    pdf.text("Seed Label Status", 340, 325, font="F2", size=8, rgb=(0.4, 0.45, 0.5))
    pdf.text("Propagated", 470, 325, font="F2", size=8, rgb=(0.4, 0.45, 0.5))

    neighbors = res.get('neighbors', [])
    y_n = 308
    for n in neighbors[:5]:
        pdf.text(n['host'][:30], 55, y_n, font="F1", size=8, rgb=(0.2, 0.25, 0.3))
        pdf.text(f"{n.get('similarity', 0):.4f}", 260, y_n, font="F3", size=8, rgb=(0.1, 0.4, 0.7))
        pdf.text(n.get('seed_status', 'Unknown')[:22], 340, y_n, font="F1", size=8, rgb=(0.3, 0.3, 0.3))
        pdf.text(f"{n.get('spread_score', 0):.2f}", 470, y_n, font="F3", size=8, rgb=(0.1, 0.1, 0.1))
        y_n -= 16

    # Footer Disclaimer
    pdf.rect(40, 60, 515, 140, fill_rgb=(0.97, 0.97, 0.98), stroke_rgb=(0.88, 0.88, 0.9))
    pdf.text("ACADEMIC MINI PROJECT RESEARCH METHODOLOGY & LIMITATIONS", 50, 185, font="F2", size=8.5, rgb=(0.2, 0.25, 0.3))
    pdf.text("1. Lexical Scope: Analysis is conducted strictly on URL string properties. No HTTP/TLS requests are initiated.", 50, 168, font="F1", size=7.5, rgb=(0.35, 0.4, 0.45))
    pdf.text("2. Uncalibrated Scores: Risk index numbers represent fuzzy synthesis, not statistical likelihood probabilities.", 50, 153, font="F1", size=7.5, rgb=(0.35, 0.4, 0.45))
    pdf.text("3. Demo Dataset Notice: Models marked as 'Synthetic Demo' are trained on repetitive .test domains for demonstration.", 50, 138, font="F1", size=7.5, rgb=(0.35, 0.4, 0.45))
    pdf.text("4. Safe URL Representation: Submitted URLs are intentionally rendered as unlinked text to prevent accidental navigation.", 50, 123, font="F1", size=7.5, rgb=(0.35, 0.4, 0.45))
    pdf.text("5. Hostname Isolation: The 25% holdout isolates exact hosts; sibling subdomains or campaigns may still share patterns.", 50, 108, font="F1", size=7.5, rgb=(0.35, 0.4, 0.45))
    pdf.text("PhishGraph Academic Research · Supervised Graph ML & Sugeno Fuzzy Logic", 50, 75, font="F2", size=7.5, rgb=(0.5, 0.55, 0.6))

    return pdf.build()


def generate_batch_pdf_report(summary, items):
    """
    Generate an executive summary PDF for batch URL analyses.
    """
    pdf = SimplePDF("PhishGraph Batch Analysis Executive Summary")
    
    # Header
    pdf.rect(0, 780, 595.28, 62, fill_rgb=(0.06, 0.09, 0.16))
    pdf.text("PHISHGRAPH · BATCH ANALYSIS EXECUTIVE REPORT", 40, 818, font="F2", size=13, rgb=(0.14, 0.75, 0.85))
    pdf.text("High-Throughput Phishing Threat Triage & Risk Distribution", 40, 802, font="F1", size=8.5, rgb=(0.8, 0.85, 0.9))

    # Summary Cards Row
    total = len(items)
    n_high = sum(1 for it in items if it.get('verdict') == 'High risk')
    n_review = sum(1 for it in items if it.get('verdict') == 'Review needed')
    n_low = sum(1 for it in items if it.get('verdict') == 'Low risk')

    pdf.rect(40, 700, 120, 65, fill_rgb=(0.95, 0.97, 1.0), stroke_rgb=(0.8, 0.88, 0.98))
    pdf.text("Total Analyzed", 50, 745, font="F2", size=8.5, rgb=(0.2, 0.3, 0.5))
    pdf.text(str(total), 50, 720, font="F2", size=18, rgb=(0.1, 0.25, 0.6))

    pdf.rect(170, 700, 120, 65, fill_rgb=(0.99, 0.93, 0.93), stroke_rgb=(0.95, 0.75, 0.75))
    pdf.text("High Risk", 180, 745, font="F2", size=8.5, rgb=(0.6, 0.1, 0.1))
    pdf.text(str(n_high), 180, 720, font="F2", size=18, rgb=(0.8, 0.1, 0.1))

    pdf.rect(300, 700, 120, 65, fill_rgb=(0.99, 0.96, 0.9), stroke_rgb=(0.95, 0.85, 0.7))
    pdf.text("Review Needed", 310, 745, font="F2", size=8.5, rgb=(0.6, 0.4, 0.0))
    pdf.text(str(n_review), 310, 720, font="F2", size=18, rgb=(0.7, 0.45, 0.0))

    pdf.rect(430, 700, 125, 65, fill_rgb=(0.93, 0.98, 0.94), stroke_rgb=(0.75, 0.92, 0.8))
    pdf.text("Low Risk", 440, 745, font="F2", size=8.5, rgb=(0.1, 0.5, 0.2))
    pdf.text(str(n_low), 440, 720, font="F2", size=18, rgb=(0.1, 0.55, 0.25))

    # Batch Items Table
    pdf.rect(40, 100, 515, 580, fill_rgb=(1, 1, 1), stroke_rgb=(0.85, 0.88, 0.92))
    pdf.text("SAMPLED BATCH ANALYSIS RESULTS", 50, 665, font="F2", size=9.5, rgb=(0.1, 0.15, 0.25))

    # Table Header
    pdf.rect(40, 642, 515, 20, fill_rgb=(0.95, 0.96, 0.98))
    pdf.text("Hostname", 50, 648, font="F2", size=8, rgb=(0.3, 0.35, 0.4))
    pdf.text("Risk Score", 250, 648, font="F2", size=8, rgb=(0.3, 0.35, 0.4))
    pdf.text("Verdict", 340, 648, font="F2", size=8, rgb=(0.3, 0.35, 0.4))
    pdf.text("Graph %", 430, 648, font="F2", size=8, rgb=(0.3, 0.35, 0.4))
    pdf.text("Lexical %", 490, 648, font="F2", size=8, rgb=(0.3, 0.35, 0.4))

    y_row = 625
    for item in items[:26]:
        v = item.get('verdict', 'Low risk')
        v_col = (0.8, 0.1, 0.1) if v == 'High risk' else ((0.7, 0.4, 0.0) if v == 'Review needed' else (0.1, 0.5, 0.2))
        pdf.text(item.get('host', 'unknown')[:32], 50, y_row, font="F1", size=7.5, rgb=(0.15, 0.2, 0.25))
        pdf.text(f"{item.get('risk_score', 0):.1f}", 250, y_row, font="F3", size=7.5, rgb=(0.1, 0.1, 0.1))
        pdf.text(v, 340, y_row, font="F2", size=7.5, rgb=v_col)
        pdf.text(f"{item.get('graph_score', 0):.1f}%", 430, y_row, font="F1", size=7.5, rgb=(0.3, 0.4, 0.5))
        pdf.text(f"{item.get('lexical_score', 0):.1f}%", 490, y_row, font="F1", size=7.5, rgb=(0.4, 0.3, 0.5))
        y_row -= 20

    # Footer
    pdf.text("Report produced by PhishGraph · Passive Lexical & Graph ML Analysis · Phishing URLs sanitized", 40, 75, font="F1", size=7.5, rgb=(0.5, 0.55, 0.6))
    return pdf.build()
