/* ============================================================
   DEMO EMAILS — completely fictional examples for learning.
   None of these use real malicious domains, real people or
   working links. All domains use the reserved ".example"
   namespace, reserved documentation IP addresses (203.0.113.x)
   or deliberately dead short links.
   ============================================================ */

const PHISHING_EXAMPLES = [

  {
    id: 'obvious',
    name: '1. Obvious phishing (expect: High Risk)',
    content:
`From: PayPal Security <security@paypa1-secure.example>
Reply-To: account-verify@world-mail.example
To: victim@example.test
Subject: URGENT!!! Final warning - your account will be suspended in 24 hours

Dear Customer,

This is your FINAL WARNING. We detected unauthorised activity on
your account. If you do not verify your account immediately, your
account will be suspended permanently within 24 hours.

Please confirm your password and enter the verification code we
just sent you, otherwise the account will be closed without
further notice.

Verify your account here: http://203.0.113.10/login.php?ref=verify

Failure to respond will result in permanent closure of your
account.

Regards,
PayPal Account Services Team

Attachment: secure_verify_form.exe`
  },

  {
    id: 'sophisticated',
    name: '2. Sophisticated phishing (expect: High Risk)',
    content:
`From: Microsoft Security <notifications@microsoft-secure-notice.example>
Reply-To: m365-review@support-desk-world.example
To: alex.morgan@example.test
Subject: Review of unusual sign-in activity to your organisation's tenant

Hello Alex,

Our monitoring system recorded a sign-in to your Microsoft 365
tenant from an unrecognised device in Warsaw, Poland at 02:14 UTC
on 3 October. The session accessed mailbox export permissions,
which is outside your organisation's normal behaviour baseline.

Please review the activity and confirm your identity to keep your
account in good standing. We ask that you validate your account
within 48 hours so the alert can be closed.

Review the sign-in: [https://admin.microsoft.com/en-us/security-review](https://account-microsoft.verify-session.example/oauth?state=8827)

If the activity was not you, sign in and follow the prompts.
Alerts that are not reviewed may result in restricted access to
your mailbox.

Kind regards,
Microsoft 365 Identity Protection

Attachment: Sign-in-report.html`
  },

  {
    id: 'm365',
    name: '3. Fake Microsoft 365 warning (expect: High Risk)',
    content:
`From: "Microsoft 365" <account-alerts@m365-secure-notice.example>
To: victim@example.test
Reply-To: recovery-verify@mailer-center.example
Subject: Action required: your Microsoft 365 account will be closed
Authentication-Results: mx.example.test; spf=fail smtp.mailfrom=m365-secure-notice.example; dkim=fail header.d=m365-secure-notice.example; dmarc=fail header.from=microsoft.com
Message-ID: <8821-fake@example.test>
Date: Wed, 7 Oct 2026 09:12:00 +0000

Dear User,

Our system has detected unusual activity on your account. Your
Microsoft 365 account will be suspended and will be closed within
12 hours unless you verify it now.

Verify your account: https://goo.gl/m365-verify-2026

You must enter your password and the verification code sent to
your phone to restore access. Do not ignore this message -
accounts that are not verified will be terminated.

Microsoft Account Team`
  },


  {
    id: 'parcel',
    name: '4. Fake parcel-delivery message (expect: Suspicious)',
    content:
`From: SwiftPost Delivery <delivery@swiftpost-track.example>
To: victim@example.test
Subject: Your parcel is on hold - action required

Your parcel SW-88231 has been held because the delivery address
could not be confirmed.

To reschedule delivery within 24 hours, confirm the delivery
address and pay the $1.99 re-delivery fee here:

https://swift-track.example/claim/SW-88231

Otherwise the parcel will be returned to sender.

SwiftPost Customer Notices

Attachment: delivery_notice.pdf.scr`
  },

  {
    id: 'bec',
    name: '5. Fake invoice / BEC style (expect: Suspicious)',
    content:
`From: finance.director@northwind-trading.example
To: sarah.kelly@example.test
Subject: Invoice INV-20487 - overdue payment

Hi Sarah,

Please find attached our invoice INV-20487 for $14,850 which is
now 30 days overdue.

Our banking details have changed with effect from this month -
please update your records and remit payment to the new account
shown on the attached remittance advice.

Could you process this today so we can close the quarter? Enable
content on the spreadsheet to view the full banking details.

Many thanks,
Jordan Hale
Finance Director, Northwind Trading

Attachment: Invoice_INV-20487.xlsx`
  },

  {
    id: 'legit',
    name: '6. Legitimate email (expect: Low Risk)',
    content:
`From: IT Service Desk <it.desk@northwind-corp.example>
To: all-staff@northwind-corp.example
Subject: Planned maintenance this Saturday (09:00-13:00)

Hello team,

The intranet will be unavailable this Saturday between 09:00 and
13:00 while we apply routine updates. No action is needed from
you.

If you have questions, reply to this message or call extension
4120 during working hours.

Thanks,
Priya Nair
IT Service Desk, Northwind Corp`
  }

];

/* Make the list visible to app.js in the browser, and to other
   tooling that reads this file as a module. */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PHISHING_EXAMPLES: PHISHING_EXAMPLES };
}

