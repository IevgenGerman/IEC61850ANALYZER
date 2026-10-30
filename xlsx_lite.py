# -*- coding: utf-8 -*-
"""
xlsx_lite.py - writes a simple .xlsx (Excel 2007+) without extra libraries.

  write(path, sheets)   sheets = [(name, header [..], rows [[..], ..], widths [..] or None), ..]
Header bold with grey fill, frozen first row, auto filter; numbers stay numbers, the rest is text.
"""
import zipfile
from xml.sax.saxutils import escape


def _col(i):
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def _cell(ref, v, style=0):
    st = ' s="%d"' % style if style else ""
    if isinstance(v, bool):
        return '<c r="%s" t="b"%s><v>%d</v></c>' % (ref, st, int(v))
    if isinstance(v, (int, float)) and v == v:
        return '<c r="%s"%s><v>%s</v></c>' % (ref, st, repr(v) if isinstance(v, float) else v)
    if v is None or v == "":
        return ""
    t = escape(str(v)).replace("\n", "&#10;")
    t = "".join(ch for ch in t if ch in "\t\n\r" or ord(ch) >= 32)
    return '<c r="%s" t="inlineStr"%s><is><t xml:space="preserve">%s</t></is></c>' % (ref, st, t)


def _sheet(header, rows, widths):
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
           '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" '
           'state="frozen"/></sheetView></sheetViews>']
    n = len(header)
    if widths is None:
        widths = []
        for i in range(n):
            m = max([len(str(header[i]))] + [len(str(r[i])) for r in rows[:2000] if i < len(r) and r[i] is not None])
            widths.append(min(max(m + 2, 8), 80))
    out.append("<cols>%s</cols>" % "".join('<col min="%d" max="%d" width="%s" customWidth="1"/>' % (i + 1, i + 1, w)
                                          for i, w in enumerate(widths)))
    out.append("<sheetData>")
    out.append('<row r="1">%s</row>' % "".join(_cell("%s1" % _col(i), h, 1) for i, h in enumerate(header)))
    for r, row in enumerate(rows, start=2):
        out.append('<row r="%d">%s</row>' % (r, "".join(_cell("%s%d" % (_col(i), r), v) for i, v in enumerate(row))))
    out.append("</sheetData>")
    if n:
        out.append('<autoFilter ref="A1:%s%d"/>' % (_col(n - 1), max(1, len(rows) + 1)))
    out.append("</worksheet>")
    return "".join(out)


def write(path, sheets):
    names = []
    for name, *_ in sheets:
        nm = "".join(c for c in name if c not in '[]:*?/\\')[:31] or "Sheet"
        while nm in names:
            nm = nm[:28] + "_%d" % len(names)
        names.append(nm)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/xl/workbook.xml" '
                   'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                   '<Override PartName="/xl/styles.xml" '
                   'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' +
                   "".join('<Override PartName="/xl/worksheets/sheet%d.xml" '
                           'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                           % (i + 1) for i in range(len(sheets))) + "</Types>")
        z.writestr("_rels/.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" '
                   'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
                   'Target="xl/workbook.xml"/></Relationships>')
        z.writestr("xl/workbook.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                   'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>' +
                   "".join('<sheet name="%s" sheetId="%d" r:id="rId%d"/>' % (escape(nm), i + 1, i + 1)
                           for i, nm in enumerate(names)) +
                   '</sheets>' +
                   "".join('<definedNames>%s</definedNames>' % "".join(
                       '<definedName name="_xlnm._FilterDatabase" localSheetId="%d" hidden="1">\'%s\'!$A$1:$%s$%d'
                       '</definedName>' % (i, escape(nm), _col(max(0, len(sheets[i][1]) - 1)),
                                           max(1, len(sheets[i][2]) + 1)) for i, nm in enumerate(names))) +
                   '</workbook>')
        z.writestr("xl/_rels/workbook.xml.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
                   "".join('<Relationship Id="rId%d" '
                           'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
                           'Target="worksheets/sheet%d.xml"/>' % (i + 1, i + 1) for i in range(len(sheets))) +
                   '<Relationship Id="rId%d" '
                   'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
                   'Target="styles.xml"/></Relationships>' % (len(sheets) + 1))
        z.writestr("xl/styles.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                   '<fonts count="2"><font><sz val="10"/><name val="Calibri"/></font>'
                   '<font><b/><sz val="10"/><name val="Calibri"/></font></fonts>'
                   '<fills count="3"><fill><patternFill patternType="none"/></fill>'
                   '<fill><patternFill patternType="gray125"/></fill>'
                   '<fill><patternFill patternType="solid"><fgColor rgb="FFD9D9D9"/><bgColor indexed="64"/>'
                   '</patternFill></fill></fills>'
                   '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
                   '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
                   '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
                   '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>'
                   '</cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/>'
                   '</cellStyles></styleSheet>')
        for i, (name, header, rows, *rest) in enumerate(sheets):
            widths = rest[0] if rest else None
            z.writestr("xl/worksheets/sheet%d.xml" % (i + 1), _sheet(header, rows, widths))
    return path
