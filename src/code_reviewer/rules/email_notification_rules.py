"""
Email and notification patterns.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class EmailNotificationRules(BaseRule):
    @property
    def name(self) -> str:
        return "email_notification"
    @property
    def description(self) -> str:
        return "Email and notification patterns"
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.BEST_PRACTICE
    @property
    def severity(self) -> Severity:
        return Severity.INFO

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        patterns = [
            # Email
            (r"email|Email|EMAIL|e-mail|E-mail|E-MAIL|mail|Mail|MAIL", "Email", "Good: email", Severity.INFO),
            (r"SMTP|smtp|IMAP|imap|POP3|pop3|POP|pop|MUA|MTA|MDA|mail|Mail|MX|DNS|DKIM|dkim|SPF|spf|DMARC|dmarc|ARC|arc|BIMI|bimi|MTA-STS|mta-sts|DANE|dane|TLSRPT|tlsrpt|RUA|rua|RUF|ruf", "Email protocol", "Good: email protocols", Severity.INFO),
            (r"sendgrid|SendGrid|SENDGRID|mailgun|Mailgun|MAILGUN|postmark|Postmark|POSTMARK|SES|ses|SES|Amazon.?SES|amazon.?ses|SparkPost|sparkpost|SPARKPOST|Mailchimp|mailchimp|MAILCHIMP|Brevo|brevo|BREVO|Mailtrap|mailtrap|MAILTRAP|EmailOctopus|emailoctopus|Moosend|moosend|MailerLite|mailerlite|ConvertKit|convertkit", "Email service", "Good: email services", Severity.INFO),
            (r"template|Template|TEMPLATE|render|Render|RENDER|variable|Variable|VARIABLE|dynamic|Dynamic|DYNAMIC|content|Content|CONTENT|body|Body|BODY|subject|Subject|SUBJECT|from|From|FROM|to|To|TO|cc|Cc|CC|bcc|Bcc|BCC|reply.?to|ReplyTo|REPLY_TO|attachment|Attachment|ATTACHMENT|inline|Inline|INLINE|header|Header|HEADER|footer|Footer|FOOTER", "Email template", "Good: email templates", Severity.INFO),
            # Notifications
            (r"notification|Notification|NOTIFICATION|alert|Alert|ALERT|message|Message|MESSAGE|push|Push|PUSH|sms|SMS|text|Text|TEXT|in.?app|InApp|in_app", "Notification type", "Good: notification types", Severity.INFO),
            (r"firebase|Firebase|FCM|fcm|APNs|apns|APNS|WebPush|webpush|web.?push|OneSignal|onesignal|Twilio|twilio|Vonage|vonage|Nexmo|nexmo|Plivo|plivo|MessageBird|messagebird|AWS.?SNS|aws.?sns|Azure.?Notification|azure.?notification|Pusher|pusher|Ably|ably|PubNub|pubnub|SocketIO|socketio|Socket\.IO", "Notification service", "Good: notification services", Severity.INFO),
            (r"rate.?limit|rateLimit|rate_limit|throttle|Throttle|dedup|Dedup|dedup|batch|Batch|BATCH|queue|Queue|QUEUE|worker|Worker|WORKER|retry|Retry|RETRY|backoff|Backoff|BACKOFF|dead.?letter|DeadLetter|dead_letter|DLQ|dlq|fallback|Fallback|FALLBACK|placeholder|Placeholder|PLACEHOLDER", "Notification patterns", "Good: notification patterns", Severity.INFO),
            (r"transactional|Transactional|TRANSACTIONAL|marketing|Marketing|MARKETING|promotional|Promotional|PROMOTIONAL|digest|Digest|DIGEST|newsletter|Newsletter|NEWSLETTER|welcome|Welcome|WELCOME|onboarding|Onboarding|ONBOARDING|reminder|Reminder|REMINDER|confirmation|Confirmation|CONFIRMATION|verification|Verification|VERIFICATION|reset|Reset|RESET|password|Password|PASSWORD|recovery|Recovery|RECOVERY", "Email type", "Good: email types", Severity.INFO),
            (r"subscribe|Subscribe|SUBSCRIBE|unsubscribe|Unsubscribe|UNSUBSCRIBE|opt.?in|optIn|opt_in|opt.?out|optOut|opt_out|consent|Consent|CONSENT|preference|Preference|PREFERENCE|frequency|Frequency|FREQUENCY|time.?zone|timezone|TIMEZONE|locale|Locale|LOCALE|language|Language|LANGUAGE", "Email preferences", "Good: email preferences", Severity.INFO),
            (r"tracking|Tracking|TRACKING|pixel|Pixel|PIXEL|analytics|Analytics|ANALYTICS|open.?rate|openRate|open_rate|click.?rate|clickRate|click_rate|bounce.?rate|bounceRate|bounce_rate|delivery.?rate|deliveryRate|delivery_rate|spam.?rate|spamRate|spam_rate|unsubscribe.?rate|unsubscribesRate|unsubscribe_rate", "Email analytics", "Good: email analytics", Severity.INFO),
            (r"spam|Spam|SPAM|phishing|Phishing|PHISHING|scam|Scam|SCAM|fraud|Fraud|FRAUD|abuse|Abuse|ABUSE|blocklist|Blocklist|BLOCKLIST|blacklist|Blacklist|BLACKLIST|allowlist|Allowlist|ALLOWLIST|whitelist|Whitelist|WHITELIST|reputation|Reputation|REPUTATION|deliverability|Deliverability|DELIVERABILITY", "Email security", "Good: email security", Severity.INFO),
            (r"attachment|Attachment|ATTACHMENT|upload|Upload|UPLOAD|file|File|FILE|document|Document|DOCUMENT|image|Image|IMAGE|link|Link|LINK|url|URL|URL|embed|Embed|EMBED|inline|Inline|INLINE|cid|CID|Content-ID|content-id", "Email attachment", "Good: email attachments", Severity.INFO),
            (r"queue|Queue|QUEUE|worker|Worker|WORKER|job|Job|JOB|task|Task|TASK|background|Background|BACKGROUND|async|Async|ASYNC|retry|Retry|RETRY|delay|Delay|DELAY|batch|Batch|BATCH|scheduled|Scheduled|SCHEDULED|cron|Cron|CRON|trigger|Trigger|TRIGGER", "Email queue", "Good: email queue", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
