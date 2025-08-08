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

pub struct MfaFactor {
    pub id: i64,
    pub user_id: i64,
    pub mfa_type: MfaFactorType,
    pub friendly_name: Option<String>,
    pub secret: String,
}
