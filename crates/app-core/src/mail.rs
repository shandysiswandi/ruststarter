use lettre::message::{MultiPart, SinglePart, header};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MailerError {
    #[error("SMTP error: {0}")]
    SmtpError(String),

    #[error("Address error: {0}")]
    AddressError(#[from] lettre::address::AddressError),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

#[derive(Debug)]
pub struct Email {
    to: String,
    subject: String,
    content: EmailContent,
}

#[derive(Debug)]
enum EmailContent {
    #[allow(dead_code)] // it's ok for now
    Text(String), // plain text only

    Multi(MultiPart), // multipart (text + html, attachments, etc.)
}

impl Email {
    pub fn build_signup_verification(to_email: &str, to_name: &str, link: &str) -> Self {
        // Plaintext fallback
        let text_body = format!(
            r#"Hi {to_name},

Thanks for signing up!

Please verify your email by clicking the link below:

{link}

This link will expire in 24 hours.

If you didn't create an account, you can safely ignore this email.

— The Rust App Team
"#,
        );

        // HTML body
        let html_body = format!(
            r#"<!DOCTYPE html>
<html>
  <body style="font-family: Arial, sans-serif;">
    <p>Hi {name},</p>
    <p>Thanks for signing up! Please verify your email by clicking the button below:</p>
    <p style="margin:20px 0;">
      <a href="{url}" style="background:#4CAF50;color:white;padding:12px 20px;
      text-decoration:none;border-radius:5px;">Verify Email</a>
    </p>
    <p>If the button doesn't work, copy and paste this link:</p>
    <p><a href="{url}">{url}</a></p>
    <p>— The Rust App Team</p>
  </body>
</html>"#,
            name = to_name,
            url = link
        );

        let multipart = MultiPart::alternative()
            .singlepart(SinglePart::builder().header(header::ContentType::TEXT_PLAIN).body(text_body))
            .singlepart(SinglePart::builder().header(header::ContentType::TEXT_HTML).body(html_body));

        Self {
            to: to_email.into(),
            subject: "Please verify your email address".into(),
            content: EmailContent::Multi(multipart),
        }
    }
}

#[async_trait::async_trait]
#[cfg_attr(feature = "testing", mockall::automock)]
pub trait Mailer: Send + Sync {
    async fn send(&self, email: Email) -> Result<(), MailerError>;
}

#[cfg(feature = "mail-local")]
pub mod local {
    use lettre::{Message, SmtpTransport, Transport};

    use super::*;

    pub struct SmtpMailer {
        transport: SmtpTransport,
        from: String,
    }

    impl SmtpMailer {
        pub fn new(host: &str, port: u16, from: String) -> Self {
            let transport = SmtpTransport::builder_dangerous(host).port(port).build();

            Self { transport, from }
        }
    }

    #[async_trait::async_trait]
    impl Mailer for SmtpMailer {
        async fn send(&self, email: Email) -> Result<(), MailerError> {
            let builder = Message::builder()
                .from(self.from.parse()?)
                .to(email.to.parse()?)
                .subject(email.subject);

            let message = match email.content {
                EmailContent::Text(body) => builder.body(body).map_err(|e| MailerError::Unknown(e.to_string()))?,

                EmailContent::Multi(multipart) => {
                    builder.multipart(multipart).map_err(|e| MailerError::Unknown(e.to_string()))?
                },
            };

            self.transport
                .send(&message)
                .map_err(|e| MailerError::SmtpError(e.to_string()))?;

            Ok(())
        }
    }
}
