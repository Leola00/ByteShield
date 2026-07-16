/**
 * Global Fraud Ops display names — simple numbered IDs + short indicative labels.
 * CASE-001 · Phishing · alinma-login  |  CMP-002 · Phishing · secure-bank
 */
(function (global) {
  "use strict";

  let caseNumberById = new Map();
  let campaignNumberByKey = new Map();

  function titleCase(value) {
    return String(value || "General")
      .replace(/_/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
  }

  function pad3(n) {
    return String(n).padStart(3, "0");
  }

  function shortHost(value) {
    let raw = String(value || "").trim();
    if (!raw) return "";
    try {
      if (raw.includes("://")) raw = new URL(raw).hostname;
    } catch {
      /* keep raw */
    }
    raw = raw.replace(/^www\./i, "");
    const label = raw.split(".")[0] || raw;
    return label.slice(0, 28);
  }

  function primaryIocHint(record) {
    if (!record) return "";
    const iocs = record.iocs || {};
    const domain =
      (iocs.domains && iocs.domains[0]) ||
      (record.urls && record.urls[0]) ||
      (iocs.urls && iocs.urls[0]);
    if (domain) return shortHost(domain);

    const email = (iocs.emails && iocs.emails[0]) || (record.emails && record.emails[0]);
    if (email) {
      const local = String(email).split("@")[0];
      return local.slice(0, 20);
    }

    const phone = (iocs.phones && iocs.phones[0]) || (record.phones && record.phones[0]);
    if (phone) return `tel-${String(phone).replace(/\D/g, "").slice(-4)}`;

    return "";
  }

  function campaignIocHint(campaign) {
    if (!campaign) return "";
    if (campaign.primaryUrl) return shortHost(campaign.primaryUrl);
    const domains = campaign.iocs && campaign.iocs.domains;
    if (domains && domains[0]) return shortHost(domains[0]);
    if (campaign.fingerprint && campaign.fingerprint.includes(":")) {
      const value = campaign.fingerprint.split(":").slice(1).join(":");
      return shortHost(value) || value.slice(0, 20);
    }
    if (campaign.fingerprint && campaign.fingerprint.includes("::")) {
      return shortHost(campaign.fingerprint.split("::")[0]);
    }
    return "";
  }

  function campaignKey(campaign) {
    return (campaign && (campaign.fingerprint || campaign.id)) || "";
  }

  function rebuildIndex(cases, campaigns) {
    caseNumberById = new Map();
    campaignNumberByKey = new Map();

    const sortedCases = (cases || [])
      .slice()
      .sort((a, b) => new Date(a.submittedAt || 0) - new Date(b.submittedAt || 0));
    sortedCases.forEach((c, index) => {
      if (c && c.id) caseNumberById.set(c.id, index + 1);
    });

    const sortedCampaigns = (campaigns || [])
      .slice()
      .sort(
        (a, b) =>
          new Date(a.firstSeenAt || a.lastSeenAt || 0) -
          new Date(b.firstSeenAt || b.lastSeenAt || 0),
      );
    sortedCampaigns.forEach((c, index) => {
      const key = campaignKey(c);
      if (key) campaignNumberByKey.set(key, index + 1);
    });
  }

  function caseDisplayId(caseRecord) {
    const n = caseRecord && caseRecord.id && caseNumberById.get(caseRecord.id);
    return n ? `CASE-${pad3(n)}` : "CASE-000";
  }

  function campaignDisplayId(campaign) {
    const key = campaignKey(campaign);
    const n = key && campaignNumberByKey.get(key);
    return n ? `CMP-${pad3(n)}` : "CMP-000";
  }

  function caseIndicativeName(caseRecord) {
    const category = titleCase(caseRecord && caseRecord.fraudCategory);
    const hint = primaryIocHint(caseRecord);
    return hint ? `${category} · ${hint}` : category;
  }

  function campaignIndicativeName(campaign) {
    const category = titleCase(campaign && campaign.fraudCategory);
    const hint = campaignIocHint(campaign);
    return hint ? `${category} · ${hint}` : category;
  }

  function caseDisplayLine(caseRecord) {
    return `${caseDisplayId(caseRecord)} · ${caseIndicativeName(caseRecord)}`;
  }

  function campaignDisplayLine(campaign) {
    return `${campaignDisplayId(campaign)} · ${campaignIndicativeName(campaign)}`;
  }

  global.FraudOpsNames = {
    rebuildIndex,
    caseDisplayId,
    campaignDisplayId,
    caseIndicativeName,
    campaignIndicativeName,
    caseDisplayLine,
    campaignDisplayLine,
    campaignKey,
  };
})(typeof window !== "undefined" ? window : globalThis);
