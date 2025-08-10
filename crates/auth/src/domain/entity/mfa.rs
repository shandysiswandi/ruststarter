use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MfaFactorType {
    Unknown,
    Totp,
    Sms,
    BackupCode,
    Whatsapp,
}

impl MfaFactorType {
    pub fn from_i16(status_code: i16) -> Self {
        match status_code {
            1 => MfaFactorType::Totp,
            2 => MfaFactorType::Sms,
            3 => MfaFactorType::BackupCode,
            4 => MfaFactorType::Whatsapp,
            _ => MfaFactorType::Unknown,
        }
    }
}

impl fmt::Display for MfaFactorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            MfaFactorType::Unknown => "Unknown",
            MfaFactorType::Totp => "Totp",
            MfaFactorType::Sms => "Sms",
            MfaFactorType::BackupCode => "BackupCode",
            MfaFactorType::Whatsapp => "Whatsapp",
        };
        write!(f, "{name}")
    }
}

#[derive(Debug, Clone)]
pub struct MfaFactor {
    pub id: i64,
    pub user_id: i64,
    pub mfa_type: MfaFactorType,
    pub friendly_name: Option<String>,
    pub secret: String,
    pub is_verified: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mfa_factor_type_from_i16() {
        assert_eq!(MfaFactorType::from_i16(1), MfaFactorType::Totp);
        assert_eq!(MfaFactorType::from_i16(2), MfaFactorType::Sms);
        assert_eq!(MfaFactorType::from_i16(3), MfaFactorType::BackupCode);
        assert_eq!(MfaFactorType::from_i16(4), MfaFactorType::Whatsapp);
        assert_eq!(MfaFactorType::from_i16(999), MfaFactorType::Unknown);
        assert_eq!(MfaFactorType::from_i16(-1), MfaFactorType::Unknown);
    }

    #[test]
    fn test_mfa_factor_type_display() {
        assert_eq!(MfaFactorType::Unknown.to_string(), "Unknown");
        assert_eq!(MfaFactorType::Totp.to_string(), "Totp");
        assert_eq!(MfaFactorType::Sms.to_string(), "Sms");
        assert_eq!(MfaFactorType::BackupCode.to_string(), "BackupCode");
        assert_eq!(MfaFactorType::Whatsapp.to_string(), "Whatsapp");
    }

    #[test]
    fn test_mfa_factor_creation() {
        let factor = MfaFactor {
            id: 42,
            user_id: 1001,
            mfa_type: MfaFactorType::Totp,
            friendly_name: Some("My Authenticator".to_string()),
            secret: "supersecret".to_string(),
            is_verified: false,
        };

        assert_eq!(factor.id, 42);
        assert_eq!(factor.user_id, 1001);
        assert_eq!(factor.mfa_type, MfaFactorType::Totp);
        assert_eq!(factor.friendly_name.as_deref(), Some("My Authenticator"));
        assert_eq!(factor.secret, "supersecret");
    }
}
