'use strict';

/* ============================================================
   PHISHING EMAIL ANALYSER — analysis engine + user interface
   ------------------------------------------------------------
   This file runs 100% inside the visitor's browser.
   It makes NO network requests. Nothing is uploaded anywhere.
   ============================================================ */

/* ------------------------------------------------------------
   1. SMALL HELPERS
   ------------------------------------------------------------ */

/* Escape text before putting it on the page (stops pasted text
   from being able to run code or alter the layout). */
function esc(value) {
  return String(value).replace(/[&<>"']/g, function (ch) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch];
  });
}

/* Find which of our pattern lists appear in the text.
   Returns the matching snippets so we can show them as evidence. */
function findPhrases(text, patterns) {
  const hits = [];
  patterns.forEach(function (re) {
    const m = text.match(re);
    if (m) hits.push(String(m[0]).trim());
  });
  return Array.from(new Set(hits));
}

/* Matches things like https://example.com/path */
const URL_RE = /(?:https?:\/\/|www\.)[^\s<>"'\])]+/gi;

function extractUrls(text) {
  const raw = text.match(URL_RE) || [];
  return Array.from(new Set(raw.map(function (u) {
    return u.replace(/[.,;:!?)\]}]+$/, '');
  })));
}

/* Pull the hostname (e.g. "mail.example.com") out of a URL. */
function hostOf(url) {
  const candidate = /^https?:\/\//i.test(url) ? url : 'http://' + url;
  try { return new URL(candidate).hostname.toLowerCase(); } catch (e) { return ''; }
}

const isIpAddress = function (host) { return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host); };

/* Find pairs of "link text" and "real destination":
   markdown style  [visible text](https://real-destination)
   HTML style      <a href="https://real-destination">visible text</a> */
function extractLinkPairs(text) {
  const pairs = [];
  let m;
  const mdRe = /\[([^\]\n]{1,300})\]\((https?:\/\/[^)\s]+)\)/gi;
  while ((m = mdRe.exec(text)) !== null) pairs.push({ visible: m[1], href: m[2] });
  const aRe = /<a\s[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  while ((m = aRe.exec(text)) !== null) {
    pairs.push({ visible: m[2].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim(), href: m[1] });
  }
  return pairs;
}

/* First URL- or domain-looking fragment inside a piece of link text. */
function firstHostish(text) {
  const m = String(text).match(/(?:https?:\/\/|www\.)[^\s<>"']+/i) ||
            String(text).match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/i);
  return m ? m[0] : '';
}

/* File attachments mentioned in the email (URLs removed first so
   "example.com/page.html" is not mistaken for an attachment). */
const FILE_RE = /\b([A-Za-z0-9][A-Za-z0-9 _\-()]{0,58})\.(exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|wsf|wsh|ps1|msi|jar|cpl|lnk|iso|img|dll|hta|reg|apk|html?|pdf|docx?|dotx?|xlsx?|xlsm|pptx?|txt|csv|rtf|zip|rar|7z|png|jpe?g|gif|svg|mp3|mp4|mbox|eml)\b/gi;

function extractFilenames(text) {
  const clean = String(text).replace(URL_RE, ' ');
  const out = [];
  let m;
  FILE_RE.lastIndex = 0;
  while ((m = FILE_RE.exec(clean)) !== null) {
    /* Skip email domains such as alerts@example.com and URL paths */
    if (m.index > 0 && (clean.charAt(m.index - 1) === '@' || clean.charAt(m.index - 1) === '/')) continue;
    let name = (m[1] + '.' + m[2]).trim();
    /* Chain a second extension — catches "invoice.pdf.exe" style tricks */
    const extra = /^\.[A-Za-z0-9]{1,5}\b/.exec(clean.slice(FILE_RE.lastIndex));
    if (extra) {
      const secondExt = extra[0].slice(1).toLowerCase();
      if (COMMON_SAFE_EXTENSIONS.indexOf(secondExt) !== -1 ||
          EXECUTABLE_EXTENSIONS.indexOf(secondExt) !== -1 ||
          secondExt === 'html' || secondExt === 'htm') {
        name += extra[0];
        FILE_RE.lastIndex += extra[0].length;
      }
    }
    out.push(name);
  }
  return Array.from(new Set(out));
}

/* ------------------------------------------------------------
   2. EMAIL HEADER PARSING (only if the user pasted headers)
   ------------------------------------------------------------ */

function splitMessage(text) {
  const sep = /\r?\n\r?\n/.exec(text);
  const firstLine = String(text).split(/\r?\n/)[0] || '';
  const looksLikeHeaders = /^\s*(from|return-path|received|delivered-to|authentication-results|received-spf|reply-to|sender|to|subject|date|message-id|dkim-signature|x-[a-z0-9-]+)\s*:/i.test(firstLine);
  if (sep && looksLikeHeaders) {
    return { headers: text.slice(0, sep.index), body: text.slice(sep.index) };
  }
  return { headers: '', body: text };
}

function emailIn(value) {
  const m = String(value).match(/[\w.+\-]+@[\w.\-]+\.[A-Za-z]{2,}/);
  return m ? m[0].toLowerCase() : '';
}

function domainOf(email) {
  const i = email.indexOf('@');
  return i === -1 ? '' : email.slice(i + 1);
}

function headerField(headers, name) {
  const re = new RegExp('^' + name + '\\s*:\\s*(.+)$', 'im');
  const m = headers.match(re);
  return m ? m[1].trim() : '';
}


/* ------------------------------------------------------------
   3. THE RULES — this is the "brain" of the analyser.
   Each rule has:
     id        - internal name
     title     - what the user sees
     category  - group name shown in the results
     cat       - CSS colour class
     points    - how much this rule adds to the score
     why       - plain-English explanation of why it matters
     detect()  - returns evidence snippets if the rule matches
   ------------------------------------------------------------ */

const BRANDS = [
  'microsoft', 'office 365', 'microsoft 365', 'paypal', 'apple', 'icloud',
  'amazon', 'google', 'netflix', 'instagram', 'facebook', 'whatsapp',
  'linkedin', 'dhl', 'fedex', 'royal mail', 'usps', 'stripe', 'docusign',
  'dropbox', 'spotify', 'coinbase', 'steam'
];

/* Which domains each brand officially uses (for link checks). */
const OFFICIAL_DOMAINS = {
  microsoft: ['microsoft.com', 'office.com', 'live.com', 'outlook.com', 'msn.com'],
  paypal: ['paypal.com', 'paypal.me'],
  apple: ['apple.com', 'icloud.com'],
  amazon: ['amazon.com', 'amazon.co.uk'],
  google: ['google.com', 'google.co.uk'],
  netflix: ['netflix.com'],
  linkedin: ['linkedin.com'],
  facebook: ['facebook.com'],
  instagram: ['instagram.com'],
  dropbox: ['dropbox.com'],
  spotify: ['spotify.com'],
  docusign: ['docusign.com']
};

const SHORTENER_DOMAINS = [
  'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd', 'ow.ly', 'buff.ly',
  'cutt.ly', 'rebrand.ly', 'shorturl.at', 'rb.gy', 'lnkd.in', 'bl.ink', 'soo.gd'
];

const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.click', '.buzz', '.loan', '.download', '.quest',
  '.gq', '.tk', '.ml', '.cf', '.rest', '.work', '.country'
];

const EXECUTABLE_EXTENSIONS = [
  'exe', 'scr', 'bat', 'cmd', 'pif', 'vbs', 'vbe', 'js', 'jse',
  'wsf', 'wsh', 'ps1', 'msi', 'jar', 'cpl', 'lnk', 'iso', 'img', 'dll',
  'hta', 'reg', 'apk'
];

const COMMON_SAFE_EXTENSIONS = [
  'pdf', 'doc', 'docx', 'dotx', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx',
  'txt', 'csv', 'rtf', 'zip', 'rar', '7z', 'png', 'jpg', 'jpeg', 'gif',
  'svg', 'mp3', 'mp4', 'mbox', 'eml',
  /* "com" is listed here on purpose: .com is technically an executable
     extension, but in email text it almost always is part of a domain
     name like example.com, which would otherwise cause false alarms. */
  'com'
];

function extensionOf(filename) {
  const parts = filename.split('.');
  return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : '';
}

const RULES = [

  /* ---- Social engineering ---- */
  {
    id: 'urgency',
    title: 'Urgency and pressure language',
    category: 'Social engineering', cat: 'social', points: 10,
    why: 'Phishing messages rush you so you act before you think. Real organisations give reasonable deadlines.',
    detect: function (ctx) {
      return findPhrases(ctx.text, [
        /\burgent(ly)?\b/i, /\bimmediately\b/i, /\bact now\b/i, /\bright away\b/i,
        /\basap\b/i, /\bfinal warning\b/i, /\blast chance\b/i,
        /\bwithin \d+ (hours?|days?)\b/i, /\bexpires? (today|soon)\b/i,
        /\btime[- ]sensitive\b/i, /\brespond (promptly|now)\b/i,
        /\bas soon as possible\b/i, /\bdo not (delay|ignore|wait)\b/i,
        /\bdon'?t (delay|wait)\b/i, /\bdeadline\b/i,
        /\bimmediate action (is )?required\b/i, /\baction required\b/i
      ]);
    }
  },
  {
    id: 'suspension',
    title: 'Threat of suspension, closure or restriction',
    category: 'Social engineering', cat: 'social', points: 15,
    why: 'Fear of losing your account is a classic pressure tactic used to push you into clicking.',
    detect: function (ctx) {
      return findPhrases(ctx.text, [
        /\bsuspend(ed|sion|ing)?\b/i, /\bdeactivat(e|ed|ion|ing)\b/i,
        /\baccount (?:will be |is )?(?:closed?|closure|terminated|deleted|locked)\b/i,
        /\btermination of (your|the) account\b/i,
        /\b(?:restricted?|restriction) (?:access|to your)\b/i,
        /\bpermanent(?:ly)? (?:closed?|suspended|disabled)\b/i
      ]);
    }
  },

  /* ---- Credential theft ---- */
  {
    id: 'passwordRequest',
    title: 'Request for your password',
    category: 'Credential theft', cat: 'credential', points: 20,
    why: 'Legitimate organisations never ask you to send or confirm your password by email.',
    detect: function (ctx) {
      return findPhrases(ctx.text, [
        /\b(password|passcode)\b[^.!?\n]{0,60}\b(confirm|verify|enter|provide|submit|update|re-?enter|share|type)\b/i,
        /\b(confirm|verify|enter|provide|submit|update|re-?enter|type)\b[^.!?\n]{0,40}\b(your\s+|the\s+)?(password|passcode|login credentials)\b/i,
        /\bpassword\b[^.!?\n]{0,40}\b(required|needed|must)\b/i
      ]);
    }
  },
  {
    id: 'mfaRequest',
    title: 'Request for an MFA / verification code',
    category: 'Credential theft', cat: 'credential', points: 20,
    why: 'One-time codes are the keys to your account. Sharing one lets an attacker log in as you.',
    detect: function (ctx) {
      return findPhrases(ctx.text, [
        /\b(verification|mfa|2fa|one[- ]time|authentication|security|login|access) codes?\b/i,
        /\bone[- ]time (password|passcode|pin)\b/i, /\botp\b/i,
        /\bcode we (just )?sent you\b/i, /\btexted you a code\b/i,
        /\bpasscode\b/i, /\bdo not share (your )?codes?\b/i
      ]);
    }
  },
  {
    id: 'credentialHarvest',
    title: 'Credential-harvesting language',
    category: 'Credential theft', cat: 'credential', points: 10,
    why: 'Wording that pushes you to "verify" or "validate" your account is how fake login pages are dressed up.',
    detect: function (ctx) {
      return findPhrases(ctx.text, [
        /\bverify your (account|identity|information|details|profile)\b/i,
        /\bconfirm your (account|identity|details)\b/i,
        /\bvalidate your (account|identity)\b/i,
        /\bunusual (sign[- ]?in|login) (activity|attempt)s?\b/i,
        /\bsuspicious (sign[- ]?in|login|activity)\b/i,
        /\brestore access\b/i,
        /\bkeep your account (active|in good standing)\b/i,
        /\bre-?authenticate\b/i, /\bunlock your account\b/i
      ]);
    }
  },


  /* ---- Financial fraud ---- */
  {
    id: 'paymentRequest',
    title: 'Payment or gift-card request',
    category: 'Financial fraud', cat: 'financial', points: 15,
    why: 'Requests for urgent payments, gift cards or crypto are almost always fraud.',
    detect: function (ctx) {
      return findPhrases(ctx.text, [
        /\bgift ?cards?\b/i, /\bitunes\b/i, /\bsteam cards?\b/i,
        /\bbitcoin\b/i, /\bcryptocurrenc(y|ies)\b/i, /\bwire transfer\b/i,
        /\bwestern union\b/i, /\bpaysafe\b/i,
        /\bpay\b/i, /\bpayments?\b/i, /\bpaying\b/i
      ]);
    }
  },
  {
    id: 'bankChange',
    title: 'Request to change bank details',
    category: 'Financial fraud', cat: 'financial', points: 15,
    why: '"Our bank details have changed" is the core move of invoice fraud and business email compromise.',
    detect: function (ctx) {
      return findPhrases(ctx.text, [
        /\bbank(?:ing)? details\b/i, /\bnew bank account\b/i,
        /\bbank account (?:has |have )?changed\b/i, /\bupdated? (our )?bank/i,
        /\biban\b/i, /\bsort code\b/i, /\bremittance\b/i,
        /\bdirect deposit details\b/i, /\bnew (payment|banking) details\b/i,
        /\bpay(?:ment)? to the new account\b/i
      ]);
    }
  },
  {
    id: 'invoiceBec',
    title: 'Unexpected invoice or payment demand',
    category: 'Financial fraud', cat: 'financial', points: 12,
    why: 'Unexpected invoices and overdue-notice emails are common in business email compromise scams.',
    detect: function (ctx) {
      return findPhrases(ctx.text, [
        /\binvoices?\b/i, /\boverdue\b/i, /\bremittance advice\b/i,
        /\bpurchase orders?\b/i, /\bunpaid balance\b/i,
        /\bbilling statements?\b/i, /\bpayment is due\b/i
      ]);
    }
  },

  /* ---- Impersonation ---- */
  {
    id: 'impersonation',
    title: 'Impersonation of a well-known brand',
    category: 'Impersonation', cat: 'impersonation', points: 10,
    why: 'Attackers borrow trusted names to look legitimate. The brand name alone proves nothing — check the real sender.',
    detect: function (ctx) {
      const hits = [];
      BRANDS.forEach(function (brand) {
        const re = new RegExp('\\b' + brand.replace(/ /g, '[\\s-]+') + '\\b', 'i');
        if (re.test(ctx.text)) hits.push('Brand mentioned: "' + brand + '"');
      });
      return hits;
    }
  },

  /* ---- Malicious attachments ---- */
  {
    id: 'macros',
    title: 'Request to enable macros / "Enable content"',
    category: 'Attachments', cat: 'attachments', points: 15,
    why: 'Macro-enabled documents are a common way to run malicious code. Legitimate documents rarely ask you to enable them.',
    detect: function (ctx) {
      return findPhrases(ctx.text, [
        /\benable (content|macros?|editing)\b/i, /\bturn on macros?\b/i,
        /\ballow macros?\b/i, /\bmacros? (must|should) be enabled\b/i,
        /\benabled editing\b/i, /\bedit to view\b/i
      ]);
    }
  },
  {
    id: 'executableAttachment',
    title: 'Executable attachment type',
    category: 'Attachments', cat: 'attachments', points: 18,
    why: 'Programs disguised as documents (.exe, .scr, .js…) run code on your computer when opened.',
    detect: function (ctx) {
      const hits = [];
      ctx.filenames.forEach(function (name) {
        const ext = extensionOf(name);
        if (EXECUTABLE_EXTENSIONS.indexOf(ext) !== -1) hits.push('Executable file: "' + name + '"');
      });
      return hits;
    }
  },
  {
    id: 'unusualAttachment',
    title: 'Unusual attachment filename',
    category: 'Attachments', cat: 'attachments', points: 12,
    why: 'Odd file types and trick names like "invoice.pdf.exe" are used to hide malware in something that looks harmless.',
    detect: function (ctx) {
      const hits = [];
      ctx.filenames.forEach(function (name) {
        const parts = name.split('.');
        const ext = extensionOf(name);
        if (parts.length > 2) {
          hits.push('Double extension (disguised filename): "' + name + '"');
        } else if (COMMON_SAFE_EXTENSIONS.indexOf(ext) === -1 &&
                   EXECUTABLE_EXTENSIONS.indexOf(ext) === -1) {
          hits.push('Unusual file type (.' + ext + '): "' + name + '"');
        }
      });
      return hits;
    }
  },


  /* ---- Suspicious links ---- */
  {
    id: 'suspiciousUrl',
    title: 'Suspicious URL',
    category: 'Suspicious links', cat: 'links', points: 12,
    why: 'Look-alike domains, unusual domain endings and unencrypted http:// links are common on fake login pages.',
    detect: function (ctx) {
      const hits = [];
      ctx.urls.forEach(function (url) {
        const host = hostOf(url);
        if (!host) return;

        /* A known brand name inside a domain that is NOT that brand's real domain */
        Object.keys(OFFICIAL_DOMAINS).forEach(function (brand) {
          if (host.indexOf(brand) !== -1) {
            const official = OFFICIAL_DOMAINS[brand];
            const ok = official.some(function (d) { return host === d || host.endsWith('.' + d); });
            if (!ok) hits.push('URL contains "' + brand + '" but is not an official ' + brand + ' address: ' + url);
          }
        });

        /* Unusual domain endings often used by attackers */
        SUSPICIOUS_TLDS.forEach(function (tld) {
          if (host.endsWith(tld)) hits.push('Unusual domain ending "' + tld + '": ' + url);
        });

        /* http://...@... trick that hides the real destination */
        if (/^https?:\/\/[^/]*@/i.test(url)) hits.push('URL uses the "@" trick to hide its real host: ' + url);

        /* Plain unencrypted http:// */
        if (/^http:\/\//i.test(url)) hits.push('Unencrypted http:// link (no TLS): ' + url);
      });
      return Array.from(new Set(hits));
    }
  },
  {
    id: 'shortenedUrl',
    title: 'Shortened URL (destination hidden)',
    category: 'Suspicious links', cat: 'links', points: 10,
    why: 'Link shorteners hide where a link really goes, so you cannot judge the destination before clicking.',
    detect: function (ctx) {
      const hits = [];
      ctx.urls.forEach(function (url) {
        const host = hostOf(url);
        SHORTENER_DOMAINS.forEach(function (d) {
          if (host === d || host.endsWith('.' + d)) hits.push('Shortened link: ' + url);
        });
      });
      return Array.from(new Set(hits));
    }
  },
  {
    id: 'rawIpUrl',
    title: 'URL using a raw IP address',
    category: 'Suspicious links', cat: 'links', points: 15,
    why: 'Real organisations link to their own domain names. A bare IP address (like http://203.0.113.10) is a strong red flag.',
    detect: function (ctx) {
      const hits = [];
      ctx.urls.forEach(function (url) {
        const host = hostOf(url);
        if (isIpAddress(host)) hits.push('IP-address link: ' + url);
      });
      return hits;
    }
  },
  {
    id: 'misleadingLink',
    title: 'Misleading link text',
    category: 'Suspicious links', cat: 'links', points: 18,
    why: 'The visible text points somewhere different from where the link actually takes you — a deliberate disguise.',
    detect: function (ctx) {
      const hits = [];
      ctx.links.forEach(function (pair) {
        const shown = firstHostish(pair.visible);
        if (!shown) return;
        const shownHost = hostOf(shown);
        const realHost = hostOf(pair.href);
        if (shownHost && realHost && shownHost !== realHost) {
          hits.push('Link text shows "' + shownHost + '" but really goes to "' + realHost + '"');
        }
      });
      return hits;
    }
  },

  /* ---- Email headers (only checked when headers were pasted) ---- */
  {
    id: 'replyToMismatch',
    title: 'Sender and Reply-To mismatch',
    category: 'Email headers', cat: 'headers', points: 15,
    why: 'The displayed sender and the address replies go to are different — replies would reach the attacker instead.',
    detect: function (ctx) {
      if (!ctx.fromEmail || !ctx.replyToEmail) return [];
      const fromDomain = domainOf(ctx.fromEmail);
      const replyDomain = domainOf(ctx.replyToEmail);
      if (fromDomain && replyDomain && fromDomain !== replyDomain) {
        return ['From: ' + ctx.fromEmail + ' but Reply-To: ' + ctx.replyToEmail];
      }
      return [];
    }
  },
  {
    id: 'spfFail',
    title: 'SPF authentication failure',
    category: 'Email headers', cat: 'headers', points: 10,
    why: 'SPF checks whether the sending server is allowed to send for that domain. "fail" means it was not.',
    detect: function (ctx) {
      return findPhrases(ctx.text, [
        /\bspf\s*=\s*fail\b/i, /\breceived-spf\s*:\s*fail\b/i
      ]);
    }
  },
  {
    id: 'dkimFail',
    title: 'DKIM authentication failure',
    category: 'Email headers', cat: 'headers', points: 10,
    why: 'DKIM checks the message was not altered and really came from that sender. "fail" breaks that trust.',
    detect: function (ctx) {
      return findPhrases(ctx.text, [/\bdkim\s*=\s*fail\b/i]);
    }
  },
  {
    id: 'dmarcFail',
    title: 'DMARC policy failure',
    category: 'Email headers', cat: 'headers', points: 12,
    why: 'DMARC combines SPF and DKIM and tells mail servers the sender domain does not authorise this message.',
    detect: function (ctx) {
      return findPhrases(ctx.text, [/\bdmarc\s*=\s*fail\b/i]);
    }
  }

];


/* ------------------------------------------------------------
   4. THE SCORING ENGINE
   Runs every rule, adds up the points, caps the total at 100
   and builds the explanation + recommendations.
   ------------------------------------------------------------ */

const HEADLINES = {
  low: 'Low risk — no strong warning signs detected',
  medium: 'Suspicious — several warning signs present',
  high: 'High risk — many phishing warning signs present'
};

function classify(score) {
  if (score >= 70) return { label: 'High Risk', level: 'high' };
  if (score >= 30) return { label: 'Suspicious', level: 'medium' };
  return { label: 'Low Risk', level: 'low' };
}

function buildRecommendations(findings, score) {
  const ids = new Set(findings.map(function (f) { return f.id; }));
  const recs = [];

  /* Always shown */
  recs.push('Do not click links or open attachments in this email in order to test them.');
  recs.push('Verify this message independently: open the organisation’s official website or app yourself, or contact them using details you already have — not links, addresses or phone numbers taken from the email.');

  if (ids.has('passwordRequest') || ids.has('mfaRequest') || ids.has('credentialHarvest')) {
    recs.push('If you already entered a password or code on a page reached from this email, change your password immediately from the official site, then review your recent sign-in activity and active sessions.');
  }
  if (ids.has('mfaRequest')) {
    recs.push('Never share MFA/verification codes. No legitimate organisation will ask you to read one out or forward it.');
  }
  if (ids.has('paymentRequest') || ids.has('bankChange') || ids.has('invoiceBec')) {
    recs.push('Before any payment or bank-detail change, confirm the request by phone using contact details you found yourself — never details printed in the email.');
  }
  if (ids.has('executableAttachment') || ids.has('unusualAttachment') || ids.has('macros')) {
    recs.push('Leave attachments closed, and never enable macros or "Enable content" because a document asked you to.');
  }
  if (ids.has('suspiciousUrl') || ids.has('shortenedUrl') || ids.has('rawIpUrl') || ids.has('misleadingLink')) {
    recs.push('Check a link’s real destination before clicking: hover your mouse over it on a computer, or long-press it on a phone, and read the actual domain.');
  }
  if (ids.has('replyToMismatch') || ids.has('spfFail') || ids.has('dkimFail') || ids.has('dmarcFail')) {
    recs.push('The sender could not be fully authenticated (see the header findings above) — treat the "From" address as unproven.');
  }
  if (ids.has('impersonation')) {
    recs.push('Do not trust the brand name in the message. Contact the organisation through its official app or website instead.');
  }

  if (score === 0) {
    recs.push('No checklist warning signs were found — but no tool can guarantee an email is safe. Stay alert to new tactics and always verify unexpected requests.');
  } else {
    recs.push('Report the message to your IT or security team if it arrived at a work or school account.');
  }

  return Array.from(new Set(recs));
}

function analyse(rawText) {
  /* Join hard-wrapped body lines so phrases that the mail client
     split across lines are still detected. Header lines and
     paragraph breaks are kept intact. */
  const split = splitMessage(rawText);
  const flatBody = String(split.body).replace(/([^\r\n])\r?\n(?!\r?\n)/g, '$1 ');
  const text = split.headers ? split.headers + flatBody : flatBody;
  const urls = extractUrls(text);

  const ctx = {
    text: text,
    headers: split.headers,
    body: split.body,
    urls: urls,
    links: extractLinkPairs(text),
    filenames: extractFilenames(text),
    fromEmail: emailIn(headerField(split.headers, 'from')),
    replyToEmail: emailIn(headerField(split.headers, 'reply-to'))
  };

  const findings = [];
  RULES.forEach(function (rule) {
    const evidence = rule.detect(ctx) || [];
    if (evidence.length > 0) {
      findings.push({
        id: rule.id,
        title: rule.title,
        category: rule.category,
        cat: rule.cat,
        points: rule.points,
        why: rule.why,
        evidence: evidence.slice(0, 6)
      });
    }
  });

  const raw = findings.reduce(function (sum, f) { return sum + f.points; }, 0);
  const score = Math.min(100, raw);
  const cls = classify(score);

  return {
    score: score,
    raw: raw,
    capped: raw > 100,
    classification: cls.label,
    level: cls.level,
    headline: HEADLINES[cls.level],
    findings: findings,
    recommendations: buildRecommendations(findings, score)
  };
}


/* ------------------------------------------------------------
   5. THE USER INTERFACE
   Draws the score, the findings and the recommendations.
   (This part only runs in a real browser.)
   ------------------------------------------------------------ */

const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 52; /* ≈ 326.73 */

function renderResults(res) {
  /* Score gauge + badge */
  const gauge = document.getElementById('gauge');
  const progress = document.getElementById('gaugeProgress');
  gauge.className = 'gauge risk-' + res.level;
  progress.style.strokeDasharray = String(GAUGE_CIRCUMFERENCE);
  progress.style.strokeDashoffset = String(GAUGE_CIRCUMFERENCE * (1 - res.score / 100));
  document.getElementById('scoreValue').textContent = String(res.score);

  const badge = document.getElementById('riskBadge');
  badge.textContent = res.classification;
  badge.className = 'risk-badge risk-' + res.level;

  document.getElementById('resultHeadline').textContent = res.headline;

  const count = res.findings.length;
  const summary = count === 0
    ? 'None of the ' + RULES.length + ' checklist rules matched this email.'
    : count + ' of the ' + RULES.length + ' checklist rules matched, contributing ' + res.raw + ' points' + (res.capped ? ' (the score is capped at 100)' : '') + '.';
  document.getElementById('scoreSummary').textContent = summary;

  /* "10 + 15 + 20 = 45 points" breakdown */
  const mathEl = document.getElementById('scoreMath');
  if (count > 0) {
    const parts = res.findings.map(function (f) { return String(f.points); });
    mathEl.textContent = parts.join(' + ') + ' = ' + res.raw + ' points' +
      (res.capped ? ' → capped at ' + res.score : ' → score ' + res.score);
  } else {
    mathEl.textContent = 'score 0 / 100';
  }

  /* Findings list */
  const list = document.getElementById('findingList');
  list.innerHTML = res.findings.map(function (f) {
    const chips = f.evidence.map(function (e) {
      return '<span class="chip">' + esc(e) + '</span>';
    }).join('');
    return '<li class="finding cat-' + f.cat + '">' +
      '<div class="finding-top"><div>' +
      '<span class="finding-title">' + esc(f.title) + '</span>' +
      '<span class="cat">' + esc(f.category) + '</span>' +
      '</div><span class="pts">+' + f.points + ' pts</span></div>' +
      '<p class="why">' + esc(f.why) + '</p>' +
      (chips ? '<div class="evidence">' + chips + '</div>' : '') +
      '</li>';
  }).join('');
  document.getElementById('noFindings').hidden = count > 0;

  /* Recommendations */
  document.getElementById('recList').innerHTML = res.recommendations.map(function (r) {
    return '<li>' + esc(r) + '</li>';
  }).join('');
}

function renderChecks() {
  /* Build the "What the analyser checks" catalogue from the rules
     themselves, so the page can never drift out of date. */
  const order = ['Social engineering', 'Credential theft', 'Financial fraud',
    'Impersonation', 'Attachments', 'Suspicious links', 'Email headers'];
  const groups = {};
  RULES.forEach(function (r) { (groups[r.category] = groups[r.category] || []).push(r); });

  let html = '';
  order.forEach(function (cat) {
    if (!groups[cat]) return;
    html += '<p class="check-cat">' + esc(cat) + '</p>';
    groups[cat].forEach(function (r) {
      html += '<article class="check-card"><h3>' + esc(r.title) +
        '<span>+' + r.points + ' pts</span></h3><p>' + esc(r.why) + '</p></article>';
    });
  });
  document.getElementById('checkList').innerHTML = html;
}

function initUI() {
  const input = document.getElementById('emailInput');
  const results = document.getElementById('results');
  const error = document.getElementById('inputError');
  const select = document.getElementById('exampleSelect');

  /* Fill the demo dropdown (examples.js provides the list) */
  const examples = (typeof PHISHING_EXAMPLES !== 'undefined') ? PHISHING_EXAMPLES : [];
  select.innerHTML = examples.map(function (ex, i) {
    return '<option value="' + i + '">' + esc(ex.name) + '</option>';
  }).join('');

  function runAnalysis() {
    const text = input.value.trim();
    if (text.length < 15) {
      error.hidden = false;
      results.hidden = true;
      input.focus();
      return;
    }
    error.hidden = true;
    const res = analyse(text);
    renderResults(res);
    results.hidden = false;
    results.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  document.getElementById('analyseBtn').addEventListener('click', runAnalysis);

  document.getElementById('loadExample').addEventListener('click', function () {
    const ex = examples[Number(select.value)];
    if (!ex) return;
    input.value = ex.content;
    error.hidden = true;
    results.hidden = true;
    input.focus();
  });

  document.getElementById('clearBtn').addEventListener('click', function () {
    input.value = '';
    results.hidden = true;
    error.hidden = true;
    input.focus();
  });

  /* Ctrl/Cmd + Enter runs the analysis */
  input.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      runAnalysis();
    }
  });

  renderChecks();
}

/* Only start the interface when a real page is present
   (this keeps the engine testable without a browser). */
if (typeof document !== 'undefined') {
  initUI();
}

/* Expose the engine for the test script. */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { analyse: analyse, RULES: RULES };
}

