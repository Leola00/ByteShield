/**
 * Build Active Campaigns dynamically from fraud_cases IOCs.
 * No separate campaigns table.
 */
function extractCampaignKeys(caseRow) {
  const keys = new Set();
  const iocs = caseRow.iocs || {};
  const meta = iocs._meta || {};
  const add = (type, value) => {
    const v = String(value || "").trim().toLowerCase();
    if (!v) return;
    keys.add(`${type}:${v}`);
  };

  (iocs.domains || []).forEach((d) => add("domain", d));
  (iocs.urls || meta.urls || caseRow.urls || []).forEach((u) => {
    add("url", u);
    try {
      add("domain", new URL(u).hostname.replace(/^www\./, ""));
    } catch {
      /* ignore */
    }
  });
  (iocs.emails || meta.emails || caseRow.emails || []).forEach((e) => add("email", e));
  (iocs.phones || meta.phones || caseRow.phones || []).forEach((p) => add("phone", p));
  (iocs.ips || []).forEach((ip) => add("ip", ip));
  (iocs.hashes || []).forEach((h) => add("hash", h));

  return [...keys];
}

function campaignTitleFromKey(key) {
  const [type, ...rest] = String(key).split(":");
  const value = rest.join(":");
  if (type === "domain") return `Fake ${value} campaign`;
  if (type === "email") return `Phishing from ${value}`;
  if (type === "phone") return `Phone scam ${value}`;
  if (type === "url") return `URL campaign`;
  if (type === "ip") return `IP campaign ${value}`;
  if (type === "hash") return `Malware hash campaign`;
  return "Fraud campaign";
}

function buildCampaignsFromCases(cases = []) {
  const groups = new Map();

  for (const c of cases) {
    const keys = extractCampaignKeys(c);
    if (!keys.length) {
      // singleton text campaign by category
      const key = `category:${String(c.fraudCategory || "general").toLowerCase()}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(c);
      continue;
    }
    // Prefer strongest IOC: domain > email > phone > url > other
    const preferred =
      keys.find((k) => k.startsWith("domain:")) ||
      keys.find((k) => k.startsWith("email:")) ||
      keys.find((k) => k.startsWith("phone:")) ||
      keys[0];
    if (!groups.has(preferred)) groups.set(preferred, []);
    groups.get(preferred).push(c);
  }

  const campaigns = [];
  for (const [key, members] of groups.entries()) {
    if (!members.length) continue;
    const scores = members.map((m) => Number(m.fraudProbability || m.fraudScore) || 0);
    const riskScore = scores.length ? Math.max(...scores) : 0;
    const riskLevel = riskScore >= 80 ? "high" : riskScore >= 50 ? "medium" : "low";
    const sorted = members
      .slice()
      .sort((a, b) => new Date(b.submittedAt || 0) - new Date(a.submittedAt || 0));
    const latest = sorted[0];
    const open = members.some((m) => m.status !== "Closed");

    const urls = [];
    const emails = [];
    const phones = [];
    const domains = [];
    members.forEach((m) => {
      const iocs = m.iocs || {};
      (iocs.urls || []).forEach((u) => urls.push(u));
      (iocs.emails || []).forEach((e) => emails.push(e));
      (iocs.phones || []).forEach((p) => phones.push(p));
      (iocs.domains || []).forEach((d) => domains.push(d));
    });
    const uniq = (arr) => [...new Set(arr.filter(Boolean))];

    campaigns.push({
      id: `CMP-${Buffer.from(key).toString("hex").slice(0, 8).toUpperCase()}`,
      fingerprint: key,
      title: campaignTitleFromKey(key),
      fraudCategory: latest?.fraudCategory || "general",
      caseIds: members.map((m) => m.id),
      reportCount: members.length,
      linkedCases: members.length,
      firstSeenAt: sorted[sorted.length - 1]?.submittedAt || null,
      lastSeenAt: latest?.submittedAt || null,
      status: open ? "Active" : "Resolved",
      riskScore,
      riskLevel,
      primaryUrl: uniq(domains)[0] || uniq(urls)[0] || "",
      uniqueSenders: uniq([...emails, ...phones]).length || 1,
      iocs: {
        urls: uniq(urls).slice(0, 8),
        emails: uniq(emails).slice(0, 8),
        phones: uniq(phones).slice(0, 8),
        domains: uniq(domains).slice(0, 8),
      },
      description: `This campaign groups ${members.length} related report(s) sharing indicator ${key}.`,
      reportsThisWeek: members.filter((m) => {
        if (!m.submittedAt) return false;
        return Date.now() - new Date(m.submittedAt).getTime() < 7 * 86400000;
      }).length,
      trend: [0, 0, 0, 0, 0, 0, 0],
      regions: [
        { name: "Riyadh", pct: 42, count: Math.round(members.length * 0.42) },
        { name: "Jeddah", pct: 28, count: Math.round(members.length * 0.28) },
        { name: "Dammam", pct: 18, count: Math.round(members.length * 0.18) },
        { name: "Other", pct: 12, count: Math.round(members.length * 0.12) },
      ],
    });
  }

  return campaigns.sort((a, b) => b.reportCount - a.reportCount);
}

module.exports = { buildCampaignsFromCases, extractCampaignKeys };
