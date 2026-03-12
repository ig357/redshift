"""
Claude-powered threat intelligence analysis.
"""

import anthropic
from datetime import datetime


def _format_articles(articles: list[dict]) -> str:
    lines = []
    for i, a in enumerate(articles, 1):
        lines.append(f"[{i}] SOURCE: {a['source']}")
        lines.append(f"    DATE:   {a['date']}")
        lines.append(f"    TITLE:  {a['title']}")
        if a["summary"]:
            lines.append(f"    DETAIL: {a['summary']}")
        if a["link"]:
            lines.append(f"    URL:    {a['link']}")
        lines.append("")
    return "\n".join(lines)


SYSTEM_PROMPT = """\
You are a senior cyber threat intelligence analyst embedded in the red team of a large retail bank.
Your job is to produce a clear, actionable daily threat briefing for a technical audience
(security engineers, red teamers, and the CISO).

Focus areas most relevant to a bank:
- Active exploitation of vulnerabilities in financial-sector technology stacks
  (Citrix, Cisco, Microsoft, Oracle, SAP, SWIFT, core banking platforms, cloud infra)
- Ransomware and extortion campaigns targeting financial institutions
- Nation-state and APT activity with a nexus to financial services
- Supply-chain attacks affecting banking software or third-party vendors
- Credential theft, phishing, and social engineering campaigns targeting bank staff or customers
- Critical CVEs (CVSS 9.0+) with active exploitation or high banking exposure
- Regulatory / compliance-relevant security incidents

Write clearly, avoid jargon where possible, and be specific about why each item matters to a bank.
"""

ANALYSIS_PROMPT_TEMPLATE = """\
Below are {count} threat intelligence articles collected today.

Review them and produce a formatted plain-text report using EXACTLY the structure shown.
Prioritise CRITICAL items first. Include a maximum of 3 items per section — pick the most
impactful ones only. Only populate INTERESTING REPORTS if there are fewer than 3 critical
items — otherwise focus depth on the critical ones.

If a section has nothing to report, write "None today." under its heading.

---

=================================================
THREAT INTELLIGENCE DAILY BRIEFING
{date}
=================================================

EXECUTIVE SUMMARY
-----------------
[Write 3–4 sentences: overall threat tempo today, key themes, any urgent actions required]

-------------------------------------------------
CRITICAL REPORTS  [immediate attention required]
-------------------------------------------------
[For each critical item:]
>> [TITLE]
   Why it matters: [1-2 sentences specific to banking]
   Key details:    [CVEs, TTPs, IOCs, affected products, exploitation status]
   Source:         [name]
   Link:           [url]

-------------------------------------------------
INTERESTING REPORTS  [awareness / watch list]
-------------------------------------------------
[For each interesting item — maximum 3, pick the most relevant to banking:]
>> [TITLE]
   Why it matters: [1 sentence]
   Key details:    [brief technical note]
   Source:         [name]
   Link:           [url]

-------------------------------------------------
ANALYST NOTES
-------------------------------------------------
[2–4 sentences on broader trends, threat landscape shifts, or recommendations]

=================================================
Articles reviewed: {count}
Report generated: {date}
=================================================

---

ARTICLES TO ANALYSE:

{articles}
"""


def analyze_with_claude(articles: list[dict]) -> str:
    """
    Send articles to Claude for analysis. Streams the response to stdout
    while building the full report string.
    """
    client = anthropic.Anthropic()

    articles_text = _format_articles(articles)
    date_str = datetime.now().strftime("%A %d %B %Y  %H:%M")

    prompt = ANALYSIS_PROMPT_TEMPLATE.format(
        count=len(articles),
        date=date_str,
        articles=articles_text,
    )

    print("\n" + "=" * 60)
    print("GENERATING REPORT (streaming)...")
    print("=" * 60 + "\n")

    report_text = ""

    with client.messages.stream(
        model="claude-opus-4-6",
        max_tokens=8192,
        thinking={"type": "adaptive"},
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    ) as stream:
        for text in stream.text_stream:
            print(text, end="", flush=True)
            report_text += text

    print()  # final newline after streaming
    return report_text