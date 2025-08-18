use chrono::{DateTime, FixedOffset, Utc};

pub fn utc_to_fixed_offset(utc_dt: &DateTime<Utc>) -> DateTime<FixedOffset> {
    let offset = FixedOffset::east_opt(0).unwrap(); // always safe
    utc_dt.with_timezone(&offset)
}
