use bip39::Language;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const NUMBERS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/";
const AMBIGUOUS: &[u8] = b"Il1O0o";

/// Password generator settings.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent generator toggles serialize directly into user preferences"
)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOptions {
    /// Total output length in Unicode scalar values (all generated values are ASCII).
    pub length: usize,
    /// Include ASCII uppercase letters.
    pub uppercase: bool,
    /// Include ASCII lowercase letters.
    pub lowercase: bool,
    /// Include decimal digits.
    pub numbers: bool,
    /// Include the built-in ASCII symbol set.
    pub symbols: bool,
    /// Minimum decimal digit count.
    pub minimum_numbers: usize,
    /// Minimum symbol count.
    pub minimum_symbols: usize,
    /// Remove commonly confused characters such as `I`, `l`, `1`, `O`, and `0`.
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 24,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            minimum_numbers: 1,
            minimum_symbols: 1,
            exclude_ambiguous: true,
        }
    }
}

/// Passphrase generator settings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassphraseOptions {
    /// Number of independently selected words.
    pub word_count: usize,
    /// Text inserted between words.
    pub separator: String,
    /// Uppercase the first letter of every word.
    pub capitalize: bool,
    /// Append one random digit to one random word.
    pub include_number: bool,
}

/// Identifier-safe random username settings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsernameOptions {
    /// Total ASCII length. The first character is always lowercase.
    pub length: usize,
    /// Minimum number of decimal digits after the first character.
    pub minimum_numbers: usize,
}

impl Default for UsernameOptions {
    fn default() -> Self {
        Self {
            length: 18,
            minimum_numbers: 2,
        }
    }
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            word_count: 6,
            separator: "-".to_owned(),
            capitalize: false,
            include_number: false,
        }
    }
}

/// Generator validation or CSPRNG failure.
#[derive(Debug, Error)]
pub enum GeneratorError {
    /// Options are inconsistent or outside supported resource bounds.
    #[error("generator settings are invalid")]
    InvalidOptions,
    /// The operating-system random source failed.
    #[error("secure random generation failed")]
    Random(#[from] getrandom::Error),
}

/// Generates a password with guaranteed minimum character counts.
///
/// # Errors
///
/// Returns [`GeneratorError::InvalidOptions`] for inconsistent bounds and
/// [`GeneratorError::Random`] if the operating-system CSPRNG fails.
pub fn generate_password(options: &PasswordOptions) -> Result<String, GeneratorError> {
    if !(8..=1024).contains(&options.length)
        || options.minimum_numbers + options.minimum_symbols > options.length
        || (options.minimum_numbers > 0 && !options.numbers)
        || (options.minimum_symbols > 0 && !options.symbols)
    {
        return Err(GeneratorError::InvalidOptions);
    }

    let filter = |set: &[u8]| -> Vec<u8> {
        set.iter()
            .copied()
            .filter(|value| !options.exclude_ambiguous || !AMBIGUOUS.contains(value))
            .collect()
    };
    let uppercase = filter(UPPERCASE);
    let lowercase = filter(LOWERCASE);
    let numbers = filter(NUMBERS);
    let symbols = filter(SYMBOLS);
    let mut pool = Vec::new();
    if options.uppercase {
        pool.extend_from_slice(&uppercase);
    }
    if options.lowercase {
        pool.extend_from_slice(&lowercase);
    }
    if options.numbers {
        pool.extend_from_slice(&numbers);
    }
    if options.symbols {
        pool.extend_from_slice(&symbols);
    }
    if pool.is_empty() {
        return Err(GeneratorError::InvalidOptions);
    }

    let mut output = Vec::with_capacity(options.length);
    for _ in 0..options.minimum_numbers {
        output.push(random_choice(&numbers)?);
    }
    for _ in 0..options.minimum_symbols {
        output.push(random_choice(&symbols)?);
    }
    while output.len() < options.length {
        output.push(random_choice(&pool)?);
    }
    secure_shuffle(&mut output)?;
    String::from_utf8(output).map_err(|_| GeneratorError::InvalidOptions)
}

/// Generates a passphrase from the audited-in crate's 2048-word BIP-39 English list.
///
/// # Errors
///
/// Returns [`GeneratorError::InvalidOptions`] for unsafe settings and
/// [`GeneratorError::Random`] if the operating-system CSPRNG fails.
pub fn generate_passphrase(options: &PassphraseOptions) -> Result<String, GeneratorError> {
    if !(3..=20).contains(&options.word_count)
        || options.separator.len() > 8
        || options.separator.chars().any(char::is_control)
    {
        return Err(GeneratorError::InvalidOptions);
    }
    let words = Language::English.word_list();
    let mut selected = Vec::with_capacity(options.word_count);
    for _ in 0..options.word_count {
        let mut word = words[random_index(words.len())?].to_owned();
        if options.capitalize {
            let mut characters = word.chars();
            if let Some(first) = characters.next() {
                word = first.to_uppercase().collect::<String>() + characters.as_str();
            }
        }
        selected.push(word);
    }
    if options.include_number {
        let index = random_index(selected.len())?;
        let number = random_index(10)?;
        selected[index].push(char::from(b'0' + u8::try_from(number).unwrap_or(0)));
    }
    Ok(selected.join(&options.separator))
}

/// Generates a site-portable random username using the operating-system CSPRNG.
///
/// The output starts with an ASCII lowercase letter and otherwise contains only
/// lowercase letters and digits, so it is accepted by conservative username
/// validators without revealing a real name or email address.
///
/// # Errors
///
/// Returns [`GeneratorError::InvalidOptions`] for inconsistent bounds and
/// [`GeneratorError::Random`] if the operating-system CSPRNG fails.
pub fn generate_username(options: &UsernameOptions) -> Result<String, GeneratorError> {
    if !(8..=128).contains(&options.length)
        || options.minimum_numbers > options.length.saturating_sub(1)
    {
        return Err(GeneratorError::InvalidOptions);
    }

    let mut tail = Vec::with_capacity(options.length - 1);
    for _ in 0..options.minimum_numbers {
        tail.push(random_choice(NUMBERS)?);
    }
    let mut pool = Vec::with_capacity(LOWERCASE.len() + NUMBERS.len());
    pool.extend_from_slice(LOWERCASE);
    pool.extend_from_slice(NUMBERS);
    while tail.len() < options.length - 1 {
        tail.push(random_choice(&pool)?);
    }
    secure_shuffle(&mut tail)?;

    let mut output = Vec::with_capacity(options.length);
    output.push(random_choice(LOWERCASE)?);
    output.extend_from_slice(&tail);
    String::from_utf8(output).map_err(|_| GeneratorError::InvalidOptions)
}

fn random_choice(values: &[u8]) -> Result<u8, GeneratorError> {
    if values.is_empty() {
        return Err(GeneratorError::InvalidOptions);
    }
    Ok(values[random_index(values.len())?])
}

fn random_index(upper: usize) -> Result<usize, GeneratorError> {
    if upper == 0 {
        return Err(GeneratorError::InvalidOptions);
    }
    let upper_u64 = u64::try_from(upper).map_err(|_| GeneratorError::InvalidOptions)?;
    let zone = u64::MAX - (u64::MAX % upper_u64);
    loop {
        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes)?;
        let value = u64::from_le_bytes(bytes);
        if value < zone {
            return usize::try_from(value % upper_u64).map_err(|_| GeneratorError::InvalidOptions);
        }
    }
}

fn secure_shuffle(values: &mut [u8]) -> Result<(), GeneratorError> {
    for index in (1..values.len()).rev() {
        let swap = random_index(index + 1)?;
        values.swap(index, swap);
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test assertions intentionally fail fast"
)]
mod tests {
    use super::*;

    #[test]
    fn password_honors_all_constraints() {
        let options = PasswordOptions {
            length: 40,
            minimum_numbers: 5,
            minimum_symbols: 4,
            ..PasswordOptions::default()
        };
        let password = generate_password(&options).unwrap();
        assert_eq!(password.len(), 40);
        assert!(password.bytes().filter(u8::is_ascii_digit).count() >= 5);
        assert!(
            password
                .bytes()
                .filter(|value| SYMBOLS.contains(value))
                .count()
                >= 4
        );
        assert!(!password.bytes().any(|value| AMBIGUOUS.contains(&value)));
    }

    #[test]
    fn passphrase_has_requested_shape() {
        let value = generate_passphrase(&PassphraseOptions {
            word_count: 7,
            separator: ".".to_owned(),
            capitalize: true,
            include_number: true,
        })
        .unwrap();
        assert_eq!(value.split('.').count(), 7);
        assert!(value.chars().any(|character| character.is_ascii_digit()));
    }

    #[test]
    fn username_is_identifier_safe_and_honors_constraints() {
        let value = generate_username(&UsernameOptions {
            length: 32,
            minimum_numbers: 6,
        })
        .unwrap();
        assert_eq!(value.len(), 32);
        assert!(value.starts_with(char::is_lowercase));
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        );
        assert!(value.bytes().filter(u8::is_ascii_digit).count() >= 6);
    }

    #[test]
    fn username_rejects_invalid_bounds() {
        assert!(
            generate_username(&UsernameOptions {
                length: 7,
                minimum_numbers: 0
            })
            .is_err()
        );
        assert!(
            generate_username(&UsernameOptions {
                length: 8,
                minimum_numbers: 8,
            })
            .is_err()
        );
    }
}
