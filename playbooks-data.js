/**
 * Fraud response playbooks for Saudi banking Fraud Ops.
 * Aligned with SAMA Cyber Security Framework and Counter-Fraud Framework (CFF).
 * Sources: https://rulebook.sama.gov.sa
 */
const FRAUD_PLAYBOOKS = [
  {
    id: 'phishing',
    title: 'Phishing & Brand Impersonation',
    tag: 'Customer-facing',
    summary: 'Fraudulent SMS, email, or websites impersonating a Saudi bank to harvest credentials or payment data.',
    sources: [
      {
        label: 'SAMA CFF — Supervisory Notifications (§3.7)',
        url: 'https://rulebook.sama.gov.sa/en/37-supervisory-notifications',
      },
      {
        label: 'SAMA CSF — Cyber Security Incident Management (§3.3.15)',
        url: 'https://rulebook.sama.gov.sa/en/3315-cyber-security-incident-management-0',
      },
    ],
    phases: [
      {
        key: 'preparation',
        title: 'PREPARATION',
        description: 'Get ready before an attack happens.',
        tasks: [
          { title: 'Publish official channel guidance', detail: 'Keep an up-to-date list of the bank\'s official app, website, and helpline. Use it to verify whether a customer message is real.' },
          { title: 'Maintain phishing domain blocklist', detail: 'Update the list of fake bank domains and URLs. Apply blocks on DNS, email, and web filters.' },
          { title: 'Tabletop exercises', detail: 'Run at least one drill each year for a mass phishing attack on retail customers.' },
          { title: 'Threat landscape monitoring', detail: 'Track new fake domains and SMS templates targeting Saudi banks.' },
        ],
      },
      {
        key: 'detection',
        title: 'DETECTION & ANALYSIS',
        description: 'Confirm what happened and how serious it is.',
        tasks: [
          { title: 'Triage customer reports', detail: 'Check the ByteShield score, message text, and campaign links. Decide if this is phishing or low-risk spam.' },
          { title: 'Identify impersonated brand', detail: 'Confirm which bank is being impersonated. Record all malicious URLs and domains.' },
          { title: 'Assess customer exposure', detail: 'Find out if any customer clicked a link, entered login details, or shared an OTP.' },
          { title: 'Evaluate significance', detail: 'Check loss amount, number of customers affected, reputational impact, and whether the attack may spread to other banks.' },
          { title: 'Document evidence', detail: 'Save screenshots, message headers, URLs, and timestamps for the case file and regulatory reporting.' },
        ],
      },
      {
        key: 'containment',
        title: 'CONTAINMENT, ERADICATION & RECOVERY',
        description: 'Stop the attack, remove the threat, and restore normal service.',
        tasks: [
          { title: 'Block malicious indicators', detail: 'Add confirmed fake domains and URLs to email, DNS, and web proxy blocklists.' },
          { title: 'Protect exposed accounts', detail: 'Reset passwords, require extra verification, or temporarily lock accounts for affected customers.' },
          { title: 'Customer outreach', detail: 'Contact customers only through official bank channels. Never reply on the suspicious thread.' },
          { title: 'Coordinate with sector partners', detail: 'Share confirmed indicators with trusted sector contacts to slow campaign spread.' },
        ],
      },
      {
        key: 'post',
        title: 'POST-INCIDENT ACTIVITY',
        description: 'Report, review, and improve controls after the incident.',
        tasks: [
          { title: 'SAMA supervisory notification', detail: 'If this is a new scam type or a significant attack, notify SAMA immediately using the official Appendix G template.' },
          { title: 'Formal incident report', detail: 'After containment, submit root cause, systems affected, customer impact, and actions taken.' },
          { title: 'Update detection rules', detail: 'Adjust ByteShield and gateway rules to catch similar messages and domains.' },
          { title: 'Lessons learned', detail: 'Record what happened, what worked, and what controls or customer guidance should improve.' },
        ],
      },
    ],
  },
  {
    id: 'otp-fraud',
    title: 'OTP / mOTP Social Engineering',
    tag: 'High urgency',
    summary: 'Customer is manipulated into sharing a one-time password or approving a fraudulent mOTP transaction.',
    sources: [
      {
        label: 'SAMA CFF — Counter-Fraud Fundamental Requirements',
        url: 'https://www.rulebook.sama.gov.sa/en/counter-fraud-fundamental-requirements',
      },
      {
        label: 'SAMA CFF — Supervisory Notifications (§3.7)',
        url: 'https://rulebook.sama.gov.sa/en/37-supervisory-notifications',
      },
    ],
    phases: [
      {
        key: 'preparation',
        title: 'PREPARATION',
        description: 'Get ready before an attack happens.',
        tasks: [
          { title: 'Customer education programme', detail: 'Reinforce that Saudi banks never request OTPs via phone, SMS, or WhatsApp (SAMA-aligned awareness messaging).' },
          { title: 'Transaction velocity controls', detail: 'Configure limits and step-up triggers for high-value or unusual mOTP approvals.' },
          { title: 'Verified callback procedure', detail: 'Document how analysts initiate outbound calls using the bank\'s published helpline only.' },
          { title: 'Fraud playbooks training', detail: 'Train frontline and fraud analysts on OTP harvesting scripts common in KSA.' },
        ],
      },
      {
        key: 'detection',
        title: 'DETECTION & ANALYSIS',
        description: 'Confirm what happened and how serious it is.',
        tasks: [
          { title: 'Confirm OTP disclosure', detail: 'Establish whether the customer shared OTP/mOTP or approved a transaction under duress.' },
          { title: 'Trace transaction chain', detail: 'Identify beneficiary account, amount, channel, device fingerprint, and session metadata.' },
          { title: 'Assess social-engineering method', detail: 'Classify as vishing, smishing, fake refund, or impersonation of bank employee.' },
          { title: 'Check linked cases', detail: 'Search for repeated senders, phone numbers, or beneficiary accounts across the case queue.' },
        ],
      },
      {
        key: 'containment',
        title: 'CONTAINMENT, ERADICATION & RECOVERY',
        description: 'Stop the attack, remove the threat, and restore normal service.',
        tasks: [
          { title: 'Stop or recall funds', detail: 'Attempt payment recall / hold with receiving institution per internal wire/card dispute procedures.' },
          { title: 'Secure customer access', detail: 'Reset credentials, revoke active sessions, and re-enrol authentication factors if compromised.' },
          { title: 'Block beneficiary rails', detail: 'Flag beneficiary IBAN/wallet/merchant for monitoring and sector reporting where applicable.' },
          { title: 'Verified customer contact', detail: 'Call customer back on file using official helpline; do not use numbers provided in the scam message.' },
        ],
      },
      {
        key: 'post',
        title: 'POST-INCIDENT ACTIVITY',
        description: 'Report, review, and improve controls after the incident.',
        tasks: [
          { title: 'Evaluate SAMA notification threshold', detail: 'Report significant external fraud or new typology to SAMA ORC/Cyber Risk Control per CFF §3.7.' },
          { title: 'FIU consideration', detail: 'Escalate to AML/FIU team if suspicion meets AML Law Art. 15 / CTF Law Art. 17 thresholds (CFF external notification requirements).' },
          { title: 'Customer restitution review', detail: 'Process dispute per bank policy and document liability determination.' },
          { title: 'Control enhancement', detail: 'Adjust mOTP friction, beneficiary cooling-off periods, or scam-detection models.' },
        ],
      },
    ],
  },
  {
    id: 'account-takeover',
    title: 'Account Takeover (ATO)',
    tag: 'Digital banking',
    summary: 'Unauthorized access to a customer\'s online or mobile banking session using stolen credentials or session tokens.',
    sources: [
      {
        label: 'SAMA CSF — Cyber Security Incident Management (§3.3.15)',
        url: 'https://rulebook.sama.gov.sa/en/3315-cyber-security-incident-management-0',
      },
      {
        label: 'SAMA CSF — Security Monitoring (§3.2.13–3.2.16)',
        url: 'https://www.rulebook.sama.gov.sa/en/entiresection/4498',
      },
    ],
    phases: [
      {
        key: 'preparation',
        title: 'PREPARATION',
        description: 'Get ready before an attack happens.',
        tasks: [
          { title: 'Session anomaly baselines', detail: 'Define normal device, geo, and behaviour profiles for digital banking users.' },
          { title: 'MFA enforcement standards', detail: 'Ensure strong authentication for high-risk actions per SAMA cyber security requirements.' },
          { title: 'Incident runbook ownership', detail: 'Assign RACI for fraud ops, IT security, and customer care during ATO events.' },
          { title: 'Log retention', detail: 'Maintain security logs for at least one year to support investigation (SAMA CSF §3.2.11).' },
        ],
      },
      {
        key: 'detection',
        title: 'DETECTION & ANALYSIS',
        description: 'Confirm what happened and how serious it is.',
        tasks: [
          { title: 'Validate unauthorized access', detail: 'Correlate login alerts, device changes, and customer dispute timing.' },
          { title: 'Identify entry vector', detail: 'Determine if access came from phishing, credential stuffing, malware, or insider assistance.' },
          { title: 'Scope affected services', detail: 'List accounts, beneficiaries, cards, and channels touched during the session.' },
          { title: 'Classify incident severity', detail: 'Rate medium/high per SAMA CSF to trigger supervisory notification if required.' },
        ],
      },
      {
        key: 'containment',
        title: 'CONTAINMENT, ERADICATION & RECOVERY',
        description: 'Stop the attack, remove the threat, and restore normal service.',
        tasks: [
          { title: 'Terminate active sessions', detail: 'Force logout across mobile and web; invalidate refresh tokens.' },
          { title: 'Lock account & cards', detail: 'Place temporary hold until customer identity is re-verified in branch or digital KYC flow.' },
          { title: 'Reverse fraudulent transactions', detail: 'Initiate recall/dispute workflows for unauthorized transfers or purchases.' },
          { title: 'Eradicate persistence', detail: 'Check for malicious devices, forwarded SMS, or enrolled payees added by attacker.' },
        ],
      },
      {
        key: 'post',
        title: 'POST-INCIDENT ACTIVITY',
        description: 'Report, review, and improve controls after the incident.',
        tasks: [
          { title: 'Notify SAMA if medium/high', detail: 'Inform SAMA IT Risk Supervision immediately for medium or high classified security incidents (CSF §3.3.15).' },
          { title: 'Root cause analysis', detail: 'Document technical and procedural root cause, impact, and corrective actions in formal report.' },
          { title: 'Media coordination', detail: 'Obtain SAMA no-objection before any public/media statement about the incident (CSF §3.3.15).' },
          { title: 'Improve detection', detail: 'Update SIEM/UEBA rules for device fingerprint and impossible-travel patterns.' },
        ],
      },
    ],
  },
  {
    id: 'sim-swap',
    title: 'SIM Swap & Telecom Fraud',
    tag: 'Telecom-linked',
    summary: 'Attacker ports or duplicates a customer\'s mobile number to intercept SMS OTP and banking notifications.',
    sources: [
      {
        label: 'SAMA CFF — Supervisory Notifications (§3.7)',
        url: 'https://rulebook.sama.gov.sa/en/37-supervisory-notifications',
      },
      {
        label: 'CITC / telecom coordination (sector practice)',
        url: 'https://www.cst.gov.sa',
      },
    ],
    phases: [
      {
        key: 'preparation',
        title: 'PREPARATION',
        description: 'Get ready before an attack happens.',
        tasks: [
          { title: 'Telecom escalation contacts', detail: 'Maintain liaison paths with mobile operators for SIM-change verification requests.' },
          { title: 'SIM-change alerting', detail: 'Alert customers and step-up authentication when SIM or MSISDN change events occur.' },
          { title: 'Alternative OTP channels', detail: 'Define fallback verification when SMS delivery is suspected compromised.' },
          { title: 'Staff verification scripts', detail: 'Train call-centre staff on SIM-swap red flags and escalation paths.' },
        ],
      },
      {
        key: 'detection',
        title: 'DETECTION & ANALYSIS',
        description: 'Confirm what happened and how serious it is.',
        tasks: [
          { title: 'Confirm SIM event', detail: 'Verify port/duplicate timing with operator and customer.' },
          { title: 'Map OTP interception window', detail: 'Identify transactions or logins occurring after the SIM change.' },
          { title: 'Collect subscriber evidence', detail: 'Gather operator ticket IDs, IMEI changes, and customer ID used at retail store if applicable.' },
          { title: 'Assess significance', detail: 'Evaluate customer loss and typology novelty for SAMA CFF notification.' },
        ],
      },
      {
        key: 'containment',
        title: 'CONTAINMENT, ERADICATION & RECOVERY',
        description: 'Stop the attack, remove the threat, and restore normal service.',
        tasks: [
          { title: 'Suspend SMS OTP reliance', detail: 'Switch customer to app-based or branch verification until SIM integrity restored.' },
          { title: 'Reverse unauthorized activity', detail: 'Hold/recall transfers executed during interception window.' },
          { title: 'Operator coordination', detail: 'Request operator investigation and reversal of fraudulent SIM change where supported.' },
          { title: 'Secure digital profile', detail: 'Reset passwords, deregister devices, and review payee list.' },
        ],
      },
      {
        key: 'post',
        title: 'POST-INCIDENT ACTIVITY',
        description: 'Report, review, and improve controls after the incident.',
        tasks: [
          { title: 'Regulatory notification', detail: 'Notify SAMA for significant external fraud or emerging typology per CFF §3.7.' },
          { title: 'Law enforcement liaison', detail: 'File report with competent authorities when criminal SIM fraud is confirmed (CFF external notification guidance).' },
          { title: 'Enhance SIM-change controls', detail: 'Tighten cooling-off periods and out-of-band confirmation for telecom events.' },
          { title: 'Sector information sharing', detail: 'Share anonymized TTPs with peer banks to prevent repeat attacks.' },
        ],
      },
    ],
  },
  {
    id: 'bec',
    title: 'Business Email Compromise (BEC)',
    tag: 'Wholesale / corporate',
    summary: 'Compromised or spoofed corporate email used to redirect vendor payments or treasury transfers.',
    sources: [
      {
        label: 'SAMA CFF — Wholesale Payment Endpoint Security Fraud (§3.7.a.4)',
        url: 'https://rulebook.sama.gov.sa/en/37-supervisory-notifications',
      },
      {
        label: 'SAMA CSF — Incident Management (§3.3.15)',
        url: 'https://rulebook.sama.gov.sa/en/3315-cyber-security-incident-management-0',
      },
    ],
    phases: [
      {
        key: 'preparation',
        title: 'PREPARATION',
        description: 'Get ready before an attack happens.',
        tasks: [
          { title: 'Dual-authorization policy', detail: 'Require multi-person approval for beneficiary changes and high-value wires.' },
          { title: 'Callback verification', detail: 'Mandate out-of-band confirmation using known contacts before payment release.' },
          { title: 'Email security controls', detail: 'Deploy SPF/DKIM/DMARC and mailbox anomaly monitoring for corporate clients.' },
          { title: 'Corporate client playbooks', detail: 'Provide BEC guidance to wholesale and SME banking customers.' },
        ],
      },
      {
        key: 'detection',
        title: 'DETECTION & ANALYSIS',
        description: 'Confirm what happened and how serious it is.',
        tasks: [
          { title: 'Validate payment instruction change', detail: 'Compare requested beneficiary details with historical payment patterns.' },
          { title: 'Analyze email headers & metadata', detail: 'Determine spoofing vs. mailbox compromise.' },
          { title: 'Quantify exposure', detail: 'Calculate transferred or at-risk amounts and affected corporate accounts.' },
          { title: 'Wholesale fraud flag', detail: 'Treat as potential Wholesale Payment Endpoint Security Fraud for SAMA assessment (CFF §3.7.a.4).' },
        ],
      },
      {
        key: 'containment',
        title: 'CONTAINMENT, ERADICATION & RECOVERY',
        description: 'Stop the attack, remove the threat, and restore normal service.',
        tasks: [
          { title: 'Payment recall', detail: 'Issue SWIFT/SARIE recall or hold messages immediately upon confirmation.' },
          { title: 'Freeze beneficiary accounts', detail: 'Coordinate with receiving bank where funds landed domestically.' },
          { title: 'Corporate credential reset', detail: 'Advise client to reset email and banking tokens; revoke API keys if applicable.' },
          { title: 'Preserve forensic evidence', detail: 'Retain emails, logs, and approval audit trail for investigation.' },
        ],
      },
      {
        key: 'post',
        title: 'POST-INCIDENT ACTIVITY',
        description: 'Report, review, and improve controls after the incident.',
        tasks: [
          { title: 'Immediate SAMA notification', detail: 'Notify SAMA Cyber Risk Control for significant wholesale payment fraud or new typology.' },
          { title: 'Formal post-incident report', detail: 'Submit impact, root cause, and remediation per SAMA CSF §3.3.15 item 7.' },
          { title: 'Client hardening review', detail: 'Recommend dual control, IP allowlists, and phishing-resistant MFA.' },
          { title: 'Update wholesale monitoring', detail: 'Tune rules for beneficiary change + high-value release within short windows.' },
        ],
      },
    ],
  },
  {
    id: 'card-fraud',
    title: 'Card Not Present (CNP) Fraud',
    tag: 'Cards & payments',
    summary: 'Unauthorized card transactions via e-commerce, mada online, or wallet payments using stolen card data.',
    sources: [
      {
        label: 'SAMA CFF — Counter-Fraud Fundamental Requirements',
        url: 'https://www.rulebook.sama.gov.sa/en/counter-fraud-fundamental-requirements',
      },
      {
        label: 'mada / scheme dispute rules (operational)',
        url: 'https://www.mada.com.sa',
      },
    ],
    phases: [
      {
        key: 'preparation',
        title: 'PREPARATION',
        description: 'Get ready before an attack happens.',
        tasks: [
          { title: 'CNP fraud thresholds', detail: 'Configure velocity, geo, and merchant-category limits aligned with card scheme rules.' },
          { title: '3-D Secure & step-up', detail: 'Ensure strong customer authentication for eligible e-commerce channels.' },
          { title: 'Dispute workflow SLAs', detail: 'Document chargeback/dispute timelines for analyst and call-centre teams.' },
          { title: 'Merchant blocklists', detail: 'Maintain high-risk MCC and merchant ID watchlists.' },
        ],
      },
      {
        key: 'detection',
        title: 'DETECTION & ANALYSIS',
        description: 'Confirm what happened and how serious it is.',
        tasks: [
          { title: 'Confirm unauthorized transactions', detail: 'Match customer dispute to authorization logs and merchant receipts.' },
          { title: 'Identify card data source', detail: 'Assess skimming, phishing, merchant breach, or dark-web dump exposure.' },
          { title: 'Cluster related cards', detail: 'Search for common merchant, IP, or device across other disputes.' },
          { title: 'Calculate loss exposure', detail: 'Sum confirmed and pending unauthorized amounts for significance testing.' },
        ],
      },
      {
        key: 'containment',
        title: 'CONTAINMENT, ERADICATION & RECOVERY',
        description: 'Stop the attack, remove the threat, and restore normal service.',
        tasks: [
          { title: 'Block card & reissue', detail: 'Hot-list PAN, disable tokens/wallets, and issue replacement card.' },
          { title: 'Merchant & MCC blocks', detail: 'Block repeat-abuse merchants or categories at authorization engine.' },
          { title: 'Provisional credit', detail: 'Apply regulatory/customer-policy credit while investigation proceeds.' },
          { title: 'File scheme dispute', detail: 'Initiate chargeback within scheme timelines where applicable.' },
        ],
      },
      {
        key: 'post',
        title: 'POST-INCIDENT ACTIVITY',
        description: 'Report, review, and improve controls after the incident.',
        tasks: [
          { title: 'SAMA notification if significant', detail: 'Escalate per CFF §3.7 when losses or customer impact meet significance thresholds.' },
          { title: 'Merchant intelligence update', detail: 'Share fraud typology with acquirer/partners when merchant compromise suspected.' },
          { title: 'Rule tuning', detail: 'Adjust authorization scoring for BIN attack or card-testing patterns.' },
          { title: 'Customer communication', detail: 'Advise on card hygiene and official dispute channels via verified bank messaging.' },
        ],
      },
    ],
  },
];
