# -*- coding: utf-8 -*-
"""Prints the exe name with the version of sniffer.py: VERSION = "v 0.4.0" -> IEC61850ANALYZER v0.4.0 """
import os, re
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "sniffer.py"), encoding="utf-8").read()
v = re.search(r'^VERSION\s*=\s*"([^"]+)"', src, re.M).group(1)
v = re.sub(r"\s*\(([^)]*)\)", r"-\1", v)
v = re.sub(r"[^\w.\-]+", "", v)
print("IEC61850ANALYZER " + v)
