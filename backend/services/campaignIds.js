/**
 * Human-readable campaign IDs derived from IOC / fingerprint (not random hex).
 * Format: CMP-{TYPE}-{SLUG} e.g. CMP-DOM-SECURE-ALINMA-LOGIN-XYZ
 */

function slugifyCampaignPart(value, maxLen = 36) {
  return String(value || "")
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, maxLen)
    .toUpperCase();
}

function campaignIdFromIndicatorKey(key) {
  const raw = String(key || "").trim();
  if (!raw) return "CMP-CAT-GENERAL";

  const colon = raw.indexOf(":");
  const type = colon >= 0 ? raw.slice(0, colon) : "category";
  const value = colon >= 0 ? raw.slice(colon + 1) : raw;

  const typeCode = {
    domain: "DOM",
    email: "EML",
    phone: "PHN",
    url: "URL",
    ip: "IP",
    hash: "HSH",
    category: "CAT",
  }[type] || "IOC";

  let slugSource = value;
  if (type === "url") {
    try {
      slugSource = new URL(value).hostname;
    } catch {
      slugSource = value;
    }
  } else if (type === "email") {
    const [local, domain] = value.split("@");
    slugSource = [local, domain].filter(Boolean).join("-");
  }

  const slug = slugifyCampaignPart(slugSource, 36);
  if (!slug) return `CMP-${typeCode}-UNKNOWN`;
  return `CMP-${typeCode}-${slug}`;
}

function campaignIdFromFingerprint(fingerprint) {
  const fp = String(fingerprint || "").trim();
  if (!fp) return "CMP-CAT-GENERAL";

  if (fp.includes(":") && !fp.includes("::")) {
    return campaignIdFromIndicatorKey(fp);
  }

  if (fp.startsWith("text::")) {
    const bits = fp.split("::");
    const category = bits[1] || "general";
    const snippet = bits.slice(2).join(" ");
    const catSlug = slugifyCampaignPart(category, 16);
    const textSlug = slugifyCampaignPart(snippet, 24);
    return textSlug ? `CMP-TXT-${catSlug}-${textSlug}` : `CMP-CAT-${catSlug}`;
  }

  const [primary, category] = fp.split("::");
  const p = String(primary || "").trim().toLowerCase();

  if (p.includes("@")) return campaignIdFromIndicatorKey(`email:${p}`);
  if (/^\+?\d[\d\s-]{6,}$/.test(p.replace(/\s/g, ""))) return campaignIdFromIndicatorKey(`phone:${p}`);
  if (p.startsWith("http://") || p.startsWith("https://")) return campaignIdFromIndicatorKey(`url:${p}`);
  if (p.includes(".")) return campaignIdFromIndicatorKey(`domain:${p}`);

  const catSlug = slugifyCampaignPart(category || "general", 20);
  const primSlug = slugifyCampaignPart(p, 24);
  return primSlug ? `CMP-IOC-${catSlug}-${primSlug}` : `CMP-CAT-${catSlug}`;
}

function resolveRepresentativeCampaignId(campaign) {
  if (!campaign) return "CMP-UNKNOWN";
  if (campaign.fingerprint) return campaignIdFromFingerprint(campaign.fingerprint);
  if (campaign.primaryUrl) {
    try {
      return campaignIdFromIndicatorKey(`domain:${new URL(campaign.primaryUrl).hostname}`);
    } catch {
      return campaignIdFromIndicatorKey(`url:${campaign.primaryUrl}`);
    }
  }
  if (campaign.fraudCategory) {
    return campaignIdFromIndicatorKey(`category:${campaign.fraudCategory}`);
  }
  return "CMP-UNKNOWN";
}

function withRepresentativeCampaignIdentity(campaign) {
  if (!campaign) return campaign;
  const id = resolveRepresentativeCampaignId(campaign);
  return {
    ...campaign,
    id,
    title: id,
    campaignId: id,
  };
}

module.exports = {
  slugifyCampaignPart,
  campaignIdFromIndicatorKey,
  campaignIdFromFingerprint,
  resolveRepresentativeCampaignId,
  withRepresentativeCampaignIdentity,
};
