use anyhow::Context as _;
use chrono::{DateTime, Utc};
use hasilan_protocol::InvitationDeliveryKind;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::authentication::Credentials,
};
use url::Url;

use crate::config::{InvitationDeliveryConfig, SmtpConfig, SmtpTls};

/// Validated invitation data passed to a delivery adapter.
pub(crate) struct Invitation<'a> {
    pub recipient: &'a str,
    pub organization_name: &'a str,
    pub token: &'a str,
    pub expires_at: DateTime<Utc>,
    pub public_url: &'a Url,
}

/// Runtime invitation-delivery boundary injected into HTTP state.
#[derive(Clone)]
pub(crate) enum InvitationDelivery {
    Manual,
    Smtp(Box<SmtpInvitationDelivery>),
}

#[derive(Clone)]
pub(crate) struct SmtpInvitationDelivery {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

/// Non-sensitive delivery failure category safe to expose to application control flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeliveryError {
    InvalidRecipient,
    Message,
    Transport,
}

impl InvitationDelivery {
    /// Builds and validates the configured adapter without making a network connection.
    pub(crate) fn from_config(config: &InvitationDeliveryConfig) -> anyhow::Result<Self> {
        match config {
            InvitationDeliveryConfig::Manual => Ok(Self::Manual),
            InvitationDeliveryConfig::Smtp(config) => SmtpInvitationDelivery::new(config)
                .map(Box::new)
                .map(Self::Smtp),
        }
    }

    pub(crate) const fn kind(&self) -> InvitationDeliveryKind {
        match self {
            Self::Manual => InvitationDeliveryKind::Manual,
            Self::Smtp(_) => InvitationDeliveryKind::Smtp,
        }
    }

    pub(crate) async fn deliver(&self, invitation: &Invitation<'_>) -> Result<(), DeliveryError> {
        match self {
            Self::Manual => Ok(()),
            Self::Smtp(delivery) => delivery.deliver(invitation).await,
        }
    }
}

impl SmtpInvitationDelivery {
    fn new(config: &SmtpConfig) -> anyhow::Result<Self> {
        let builder = match config.tls {
            SmtpTls::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host),
            SmtpTls::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host),
        }
        .context("cannot configure the TLS SMTP relay")?
        .port(config.port)
        .timeout(Some(config.timeout));
        let builder = match (&config.username, &config.password) {
            (Some(username), Some(password)) => builder.credentials(Credentials::new(
                username.clone(),
                password.expose().to_owned(),
            )),
            (None, None) => builder,
            _ => anyhow::bail!("SMTP credentials are incomplete"),
        };
        let from = config
            .from
            .parse::<Mailbox>()
            .context("cannot parse HP_SMTP_FROM")?;
        Ok(Self {
            transport: builder.build(),
            from,
        })
    }

    async fn deliver(&self, invitation: &Invitation<'_>) -> Result<(), DeliveryError> {
        let message = self.message(invitation)?;
        self.transport
            .send(message)
            .await
            .map(|_| ())
            .map_err(|_| DeliveryError::Transport)
    }

    fn message(&self, invitation: &Invitation<'_>) -> Result<Message, DeliveryError> {
        let recipient = invitation
            .recipient
            .parse::<Mailbox>()
            .map_err(|_| DeliveryError::InvalidRecipient)?;
        let mut invitation_url = invitation.public_url.clone();
        invitation_url.set_query(None);
        invitation_url.set_fragment(Some(&format!("invitation={}", invitation.token)));
        let body = format!(
            "You have been invited to the Hasilan Pass organization \"{}\".\n\nOpen the Web Vault, choose Organizations, and accept this invitation with the token below. The URL fragment also carries the token without sending it to the web server.\n\nWeb Vault: {}\n\nInvitation token:\n{}\n\nExpires: {}\n\nIf you did not expect this invitation, ignore this message.\n",
            invitation.organization_name,
            invitation_url,
            invitation.token,
            invitation.expires_at.to_rfc3339(),
        );
        Message::builder()
            .from(self.from.clone())
            .to(recipient)
            .subject("Hasilan Pass organization invitation")
            .header(ContentType::TEXT_PLAIN)
            .body(body)
            .map_err(|_| DeliveryError::Message)
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::*;
    use crate::config::{SmtpPassword, SmtpTls};

    fn smtp_delivery() -> SmtpInvitationDelivery {
        let config = SmtpConfig {
            host: "smtp.example.test".to_owned(),
            port: 587,
            tls: SmtpTls::StartTls,
            from: "Hasilan Pass <noreply@example.test>".to_owned(),
            username: Some("fixture-user".to_owned()),
            password: Some(Arc::new(SmtpPassword::new_for_test("fixture-password"))),
            timeout: Duration::from_secs(5),
        };
        SmtpInvitationDelivery::new(&config).unwrap_or_else(|error| panic!("{error}"))
    }

    #[tokio::test]
    async fn invitation_message_uses_plain_text_and_fragment_token() {
        let delivery = smtp_delivery();
        let public_url = Url::parse("https://vault.example.test/path?discard=me")
            .unwrap_or_else(|error| panic!("{error}"));
        let invitation = Invitation {
            recipient: "alice@example.test",
            organization_name: "Engineering",
            token: "fixture-token_123",
            expires_at: Utc::now(),
            public_url: &public_url,
        };
        let formatted = delivery
            .message(&invitation)
            .unwrap_or_else(|error| panic!("{error:?}"))
            .formatted();
        let formatted = String::from_utf8(formatted).unwrap_or_else(|error| panic!("{error}"));
        assert!(formatted.contains("Content-Type: text/plain"));
        assert!(
            formatted.contains("https://vault.example.test/path#invitation=3Dfixture-token_123"),
            "{formatted}"
        );
        assert!(!formatted.contains("discard=me"));
        assert!(formatted.contains("alice@example.test"));
    }

    #[tokio::test]
    async fn manual_adapter_does_not_expose_a_network_dependency() {
        let public_url =
            Url::parse("https://vault.example.test").unwrap_or_else(|error| panic!("{error}"));
        let invitation = Invitation {
            recipient: "alice@example.test",
            organization_name: "Engineering",
            token: "fixture-token",
            expires_at: Utc::now(),
            public_url: &public_url,
        };
        let delivery = InvitationDelivery::Manual;
        assert_eq!(delivery.kind(), InvitationDeliveryKind::Manual);
        assert_eq!(delivery.deliver(&invitation).await, Ok(()));
    }
}
