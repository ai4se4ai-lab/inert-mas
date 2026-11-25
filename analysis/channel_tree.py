"""Channel tree (Figure 2): attack forms per channel with control class, INERT mechanism, property and
coverage criterion. Generates the TikZ body between the %<<channel_tree>> markers of main.tex.

  python analysis/channel_tree.py [main.tex]
"""
# rows: (band, channel, attack form line1, line2, control, mechanism l1, l2, property, criteria)
rows = [
 (0,"C1","Injected suffix in the user's request","direct injection","S","input label on the","injected suffix","P5","TAINT"),
 (0,"C2","Data becomes a worker's sub-task","data-to-instruction","S","taint check at context","selection (MP1)","P5","SEL"),
 (0,"C2","Data becomes a recipient, path","or command, data-to-executor","S","taint check at accept-","ance and tool call","P5","TAINT\\\\EDGE"),
 (0,"C3","Fake error or status routes control","control-flow hijack","T","fixed compiled plan","","P1","EDGE"),
 (1,"C4","Payload copied from agent to agent","self-replication","S","labels propagate","inside envelopes","P5","EDGE\\\\SEL"),
 (1,"C4","Sender impersonation","``as the orchestrator, I instruct''","T","per-request","capability tokens","P2","SLOT"),
 (1,"C4","Message rewritten in transit","agent-in-the-middle","T","MAC over request,","key and value","P2","EDGE"),
 (1,"C5","Replay of a stale approval or result","","T","exact dependency-","key match","P3","RECONF"),
 (1,"C5","Release of an inconsistent snapshot","","T","publication barrier","","P6","SLOT\\\\COLL"),
 (1,"C5","Colluding agents agree on a decision","","R","owned validators","narrow the choice","P4","COLL"),
 (2,"C6","Poisoned record read in a later task","","S","not mediated:","gap G5","--","--"),
 (2,"C7","Poisoned tool description","tool poisoning","T","tool hash pinned","in the contract","P4","RECONF"),
 (2,"C7","Rogue agent or provider registration","","T","ownership bound","to the plan","P2,P4","RECONF"),
 (3,"*","Compromised owner misuses","its own authority (cross-cutting)","R","owned validators;","task scope (I2S)","P4","SLOT\\\\COLL"),
]
chan = {"C1":"C1 User request","C2":"C2 External\\\\content","C3":"C3 Tool response","C4":"C4 Peer\\\\message",
        "C5":"C5 Coordination\\\\signal","C6":"C6 Shared state","C7":"C7 Discovery\\\\metadata","*":"Any channel"}
bands = [("Entry","tier0"),("Collaboration","tier1"),("Persist.,\\\\config.","tier2"),("","tierx")]
ctl = {"S":("semantic","clsM"),"T":("structural","clsS"),"R":("residual","clsR")}
RH, GAP = 0.62, 0.16
# x columns (cm), total width 13.0
XB0, XB1 = 0.0, 0.55
XC0, XC1 = 0.65, 2.75
XA, XK, XM, XP, XR, XEND = 2.9, 7.75, 9.0, 11.45, 12.2, 13.05
ys = []
y = 0.0
prev = None
for r in rows:
    if prev is not None and r[0] != prev:
        y -= GAP
    ys.append(y)
    y -= RH
    prev = r[0]
out = []
F7 = r"\sffamily\fontsize{6.6}{7.6}\selectfont"
F6 = r"\sffamily\fontsize{5.9}{6.8}\selectfont"
out.append(r"\begin{tikzpicture}[x=1cm,y=1cm,every node/.style={inner sep=0pt,font="+F7+"}]")
# headers
hy=0.42
for x,t in [(XB0,"Class"),(XC0,"Channel"),(XA,"Attack form"),(XK,"Control"),(XM,"INERT mechanism"),(XP,"Prop."),(XR,"Criterion")]:
    out.append(rf"\node[anchor=west,font={F6}\bfseries,text=black!65] at ({x},{hy}) {{{t}}};")
out.append(rf"\draw[black!35] ({XB0},0.22) -- ({XEND},0.22);")
# zebra rows
for i, yy in enumerate(ys):
    if i % 2 == 0:
        out.append(rf"\fill[black!3] ({XA-0.1},{yy+RH/2-0.02}) rectangle ({XEND},{yy-RH/2+0.02});")
# bands
for b,(lab,col) in enumerate(bands):
    idx = [i for i, r in enumerate(rows) if r[0] == b]
    top = ys[idx[0]] + RH / 2 - 0.02
    bot = ys[idx[-1]] - RH / 2 + 0.02
    out.append(rf"\fill[{col},rounded corners=1.5pt] ({XB0},{top}) rectangle ({XB1},{bot});")
    rot = "rotate=90," if len(idx)>1 else ""
    fs = F6 if len(idx)>1 else r"\fontsize{5.2}{6}\selectfont"
    out.append(rf"\node[{rot}text=white,align=center,font={fs}\bfseries] at ({(XB0+XB1)/2},{(top+bot)/2}) {{{lab}}};")
    out.append(rf"\draw[{col}!45,line width=0.4pt] ({XC0-0.05},{top}) -- ({XEND},{top});")
# channel boxes spanning their rows
i = 0
while i<len(rows):
    j = i
    while j+1<len(rows) and rows[j+1][1]==rows[i][1] and rows[j+1][0]==rows[i][0]:
        j += 1
    top = ys[i] + RH / 2 - 0.05
    bot = ys[j] - RH / 2 + 0.05
    col = bands[rows[i][0]][1]
    out.append(rf"\draw[{col},fill={col}!8,rounded corners=2pt] ({XC0},{top}) rectangle ({XC1},{bot});")
    out.append(rf"\node[align=left,anchor=west] at ({XC0+0.1},{(top+bot)/2}) {{{chan[rows[i][1]]}}};")
    i = j + 1
# rows
for r, yy in zip(rows, ys, strict=True):
    a1, a2 = r[2], r[3]
    att = a1 if not a2 else a1+r"\\[-0.5pt]{\color{black!55}"+F6+r"\itshape "+a2+"}"
    out.append(rf"\node[align=left,anchor=west] at ({XA},{yy}) {{{att}}};")
    word, col = ctl[r[4]]
    out.append(rf"\node[fill={col},text=white,rounded corners=1.2pt,minimum width=1.12cm,minimum height=0.32cm,inner xsep=1pt,font={F6}\bfseries] at ({XK+0.6},{yy}) {{{word}}};")
    m = r[5] if not r[6] else r[5]+r"\\"+r[6]
    out.append(rf"\node[align=left,anchor=west] at ({XM},{yy}) {{{m}}};")
    out.append(rf"\node[anchor=west,font={F7}\bfseries] at ({XP},{yy}) {{{r[7]}}};")
    out.append(rf"\node[align=left,anchor=west,font=\ttfamily{F6}] at ({XR},{yy}) {{{r[8]}}};")
out.append(r"\end{tikzpicture}")

def main() -> int:
    import re
    import sys
    from pathlib import Path
    p = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/paper/EMSE/Springer-Nature-LaTeX-template/main.tex")
    s = p.read_text()
    body = "\n".join(out)
    s = re.sub(r"(%<<channel_tree>>\n).*?(\n%<</channel_tree>>)", lambda m: m.group(1) + body + m.group(2), s, flags=re.S)
    p.write_text(s)
    print("channel tree:", len(rows), "attack forms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
