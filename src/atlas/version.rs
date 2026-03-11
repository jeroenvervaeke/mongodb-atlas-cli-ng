use std::fmt;
use std::str::FromStr;

const PREFIX: &str = "application/vnd.atlas.";
const PREVIEW_SUFFIX: &str = "preview";
const UPCOMING_SUFFIX: &str = ".upcoming";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Version {
    Date(VersionDate),
    Preview(VersionPreview),
    Upcoming(VersionUpcoming),
}

impl Version {
    pub fn date(year: u16, month: u8, day: u8) -> Self {
        Self::Date(VersionDate(Date { year, month, day }))
    }

    pub fn preview() -> Self {
        Self::Preview(VersionPreview)
    }

    pub fn upcoming(year: u16, month: u8, day: u8) -> Self {
        Self::Upcoming(VersionUpcoming(Date { year, month, day }))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum VersionError {
    #[error("missing prefix")]
    MissingPrefix,

    #[error(transparent)]
    InvalidDate(#[from] DateError),
}

impl TryFrom<&str> for Version {
    type Error = VersionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // Strip the prefix
        // We should be left with either: YYYY-MM-DD or preview or YYYY-MM-DD.upcoming
        let value = value
            .strip_prefix(PREFIX)
            .ok_or(VersionError::MissingPrefix)?;

        // Check if the value is a preview version
        if value == PREVIEW_SUFFIX {
            return Ok(Version::Preview(VersionPreview));
        }

        // Check if the value is an upcoming version
        if let Some(date) = value.strip_suffix(UPCOMING_SUFFIX) {
            return Ok(Version::Upcoming(VersionUpcoming(Date::from_str(date)?)));
        }

        // The value is a date
        Ok(Version::Date(VersionDate(Date::from_str(value)?)))
    }
}

impl FromStr for Version {
    type Err = VersionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VersionDate(Date);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Date {
    year: u16,
    month: u8,
    day: u8,
}

#[derive(thiserror::Error, Debug)]
pub enum DateError {
    #[error("invalid date format, expected YYYY-MM-DD")]
    InvalidDateFormat,
}

fn next_date_part<'a, T: FromStr, I: Iterator<Item = &'a str>>(
    parts: &mut I,
) -> Result<T, DateError> {
    parts
        .next()
        .ok_or(DateError::InvalidDateFormat)?
        .parse::<T>()
        .map_err(|_| DateError::InvalidDateFormat)
}

impl TryFrom<&str> for Date {
    type Error = DateError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut parts = value.splitn(3, '-');

        let year = next_date_part(&mut parts)?;
        let month = next_date_part(&mut parts)?;
        let day = next_date_part(&mut parts)?;

        Ok(Date { year, month, day })
    }
}

impl FromStr for Date {
    type Err = DateError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VersionPreview;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VersionUpcoming(Date);

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Version::Date(VersionDate(date)) => write!(f, "{PREFIX}{date}"),
            Version::Preview(_) => write!(f, "{PREFIX}{PREVIEW_SUFFIX}"),
            Version::Upcoming(VersionUpcoming(date)) => {
                write!(f, "{PREFIX}{date}{UPCOMING_SUFFIX}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parse_preview() {
        let v = Version::try_from("application/vnd.atlas.preview").unwrap();
        assert!(matches!(v, Version::Preview(_)));
    }

    #[test]
    fn version_parse_date() {
        let v = Version::try_from("application/vnd.atlas.2024-01-15").unwrap();
        assert!(matches!(v, Version::Date(_)));
    }

    #[test]
    fn version_parse_date_edge() {
        let v = Version::try_from("application/vnd.atlas.2000-12-31").unwrap();
        assert!(matches!(v, Version::Date(_)));
    }

    #[test]
    fn version_parse_upcoming() {
        let v = Version::try_from("application/vnd.atlas.2024-01-15.upcoming").unwrap();
        assert!(matches!(v, Version::Upcoming(_)));
    }

    #[test]
    fn version_parse_upcoming_edge() {
        let v = Version::try_from("application/vnd.atlas.1999-01-01.upcoming").unwrap();
        assert!(matches!(v, Version::Upcoming(_)));
    }

    #[test]
    fn version_parse_missing_prefix_empty() {
        let err = Version::try_from("").unwrap_err();
        assert!(matches!(err, VersionError::MissingPrefix));
    }

    #[test]
    fn version_parse_missing_prefix_no_prefix() {
        let err = Version::try_from("2024-01-15").unwrap_err();
        assert!(matches!(err, VersionError::MissingPrefix));
    }

    #[test]
    fn version_parse_missing_prefix_wrong_prefix() {
        let err = Version::try_from("vnd.atlas.2024-01-15").unwrap_err();
        assert!(matches!(err, VersionError::MissingPrefix));
    }

    #[test]
    fn version_parse_missing_prefix_wrong_vendor() {
        let err = Version::try_from("application/vnd.other.2024-01-15").unwrap_err();
        assert!(matches!(err, VersionError::MissingPrefix));
    }

    #[test]
    fn version_parse_prefix_only_empty_remainder() {
        let err = Version::try_from("application/vnd.atlas.").unwrap_err();
        assert!(matches!(err, VersionError::InvalidDate(_)));
    }

    #[test]
    fn version_parse_invalid_date_not_a_date() {
        let err = Version::try_from("application/vnd.atlas.not-a-date").unwrap_err();
        assert!(matches!(err, VersionError::InvalidDate(_)));
    }

    #[test]
    fn version_parse_invalid_date_too_few_parts() {
        let err = Version::try_from("application/vnd.atlas.2024-01").unwrap_err();
        assert!(matches!(err, VersionError::InvalidDate(_)));
    }

    #[test]
    fn version_parse_invalid_date_extra_junk() {
        let err = Version::try_from("application/vnd.atlas.2024-01-15-00").unwrap_err();
        assert!(matches!(err, VersionError::InvalidDate(_)));
    }

    #[test]
    fn version_parse_preview_extra_not_preview() {
        let err = Version::try_from("application/vnd.atlas.preview.extra").unwrap_err();
        assert!(matches!(err, VersionError::InvalidDate(_)));
    }

    #[test]
    fn version_parse_upcoming_extra() {
        let err = Version::try_from("application/vnd.atlas.2024-01-15.upcoming.extra").unwrap_err();
        assert!(matches!(err, VersionError::InvalidDate(_)));
    }

    #[test]
    fn version_parse_upcoming_case_sensitive() {
        let err = Version::try_from("application/vnd.atlas.2024-01-15.Upcoming").unwrap_err();
        assert!(matches!(err, VersionError::InvalidDate(_)));
    }

    #[test]
    fn version_from_str() {
        let v: Version = "application/vnd.atlas.preview".parse().unwrap();
        assert!(matches!(v, Version::Preview(_)));
    }

    #[test]
    fn version_display_date() {
        assert_eq!(
            Version::date(2024, 10, 23).to_string(),
            "application/vnd.atlas.2024-10-23"
        );
    }

    #[test]
    fn version_display_date_pads_month_and_day() {
        assert_eq!(
            Version::date(2024, 1, 5).to_string(),
            "application/vnd.atlas.2024-01-05"
        );
    }

    #[test]
    fn version_display_preview() {
        assert_eq!(
            Version::preview().to_string(),
            "application/vnd.atlas.preview"
        );
    }

    #[test]
    fn version_display_upcoming() {
        assert_eq!(
            Version::upcoming(2024, 10, 23).to_string(),
            "application/vnd.atlas.2024-10-23.upcoming"
        );
    }

    #[test]
    fn version_display_roundtrips_with_parse() {
        let versions = [
            Version::date(2024, 10, 23),
            Version::preview(),
            Version::upcoming(2025, 3, 1),
        ];
        for v in versions {
            let s = v.to_string();
            let parsed: Version = s.parse().unwrap();
            assert_eq!(v, parsed);
        }
    }

    #[test]
    fn date_parse_valid() {
        let _ = Date::from_str("2024-01-15").unwrap();
    }

    #[test]
    fn date_parse_too_few_parts() {
        let err = Date::from_str("2024-01").unwrap_err();
        assert!(matches!(err, DateError::InvalidDateFormat));
    }

    #[test]
    fn date_parse_not_a_date() {
        let err = Date::from_str("not-a-date").unwrap_err();
        assert!(matches!(err, DateError::InvalidDateFormat));
    }

    #[test]
    fn date_parse_empty() {
        let err = Date::from_str("").unwrap_err();
        assert!(matches!(err, DateError::InvalidDateFormat));
    }
}
