# Phishing Email Analyser

A free, educational web tool that reads a pasted email and reports the
phishing and social-engineering warning signs it contains, with an
explainable risk score out of 100.

## Privacy first

All analysis happens **inside your browser**. The site makes no network
requests with your email content. There is no backend, no database, no
accounts, no API keys, no analytics and no trackers of any kind. Your
email text is never uploaded anywhere.

## Files

| File | Purpose |
|---|---|
| `index.html` | The page itself: layout and all wording |
| `style.css` | The visual design: colours, spacing, mobile layout |
| `app.js` | The analysis engine (the rules and scoring) plus the interface code |
| `examples.js` | Six fictional demo emails shown in the "Demo emails" dropdown |
| `README.md` | This guide |

## How to run it

No installation and no tools are required.

1. Open the folder that contains these files.
2. Double-click `index.html`.
3. It opens in your web browser; that's the whole app running locally.

## How the scoring works

`app.js` contains a list called `RULES`. Every rule has a fixed point
value. When a rule matches the pasted text, its points are added up and
capped at 100:

- **0–29 → Low Risk**
- **30–69 → Suspicious**
- **70–100 → High Risk**

The results panel shows each rule that fired, its points, and the exact
text that triggered it, so the score is always explainable.

### Changing a score

Open `app.js`, find the rule (each one has a comment with its name), and
change its `points` number. Keep values sensible so the score stays
meaningful.

### Adding a demo email

Open `examples.js` and copy one of the existing blocks in the
`PHISHING_EXAMPLES` list. Give it a new `id`, `name` and `content`.

## Limitations

This is an **educational triage tool**. It highlights common warning
signs; it can never definitively determine whether an email is malicious
or safe. It performs pattern matching only it does not sandbox
attachments, visit links, or contact any service.

- Never click links or open attachments in a suspicious email just to
  test them.
- Verify important messages independently using the organisation's
  official website, app, or contact details you already trust.
- Never share passwords or MFA/verification codes with anyone.
