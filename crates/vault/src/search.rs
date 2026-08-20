use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ItemData, VaultItem};

/// A local search result with deterministic relevance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SearchHit {
    /// Matching vault item identifier.
    pub id: Uuid,
    /// Deterministic relevance score; larger values sort first.
    pub score: u32,
}

/// Searches only already-decrypted in-memory items.
#[must_use]
pub fn search(items: &[VaultItem], query: &str) -> Vec<SearchHit> {
    let terms: Vec<String> = query
        .split_whitespace()
        .map(str::to_lowercase)
        .filter(|term| !term.is_empty())
        .collect();
    if terms.is_empty() {
        return items
            .iter()
            .filter(|item| item.deleted_date.is_none())
            .map(|item| SearchHit {
                id: item.id,
                score: u32::from(item.favorite),
            })
            .collect();
    }

    let mut hits = Vec::new();
    for item in items.iter().filter(|item| item.deleted_date.is_none()) {
        let mut fields = vec![(item.name.to_lowercase(), 100_u32)];
        if let Some(notes) = &item.notes {
            fields.push((notes.to_lowercase(), 10));
        }
        if let ItemData::Login(login) = &item.data {
            if let Some(username) = &login.username {
                fields.push((username.to_lowercase(), 60));
            }
            fields.extend(login.uris.iter().map(|uri| (uri.uri.to_lowercase(), 50)));
        }
        for field in &item.fields {
            if let Some(name) = &field.name {
                fields.push((name.to_lowercase(), 20));
            }
            if let Some(value) = &field.value {
                fields.push((value.expose().to_lowercase(), 10));
            }
        }
        if terms
            .iter()
            .all(|term| fields.iter().any(|(value, _)| value.contains(term)))
        {
            let score = terms
                .iter()
                .map(|term| {
                    fields
                        .iter()
                        .filter(|(value, _)| value.contains(term))
                        .map(|(_, weight)| *weight)
                        .max()
                        .unwrap_or(0)
                })
                .sum::<u32>()
                + u32::from(item.favorite) * 5;
            hits.push(SearchHit { id: item.id, score });
        }
    }
    hits.sort_by(|left, right| right.score.cmp(&left.score).then(left.id.cmp(&right.id)));
    hits
}

#[cfg(test)]
mod tests {
    use crate::{Login, SecretString};

    use super::*;

    #[test]
    fn searches_name_username_notes_uri_and_custom_fields() {
        let mut item = VaultItem::new_login(
            "Production Portal",
            Login {
                username: Some("alice@example.com".to_owned()),
                password: Some(SecretString::new("not-indexed")),
                ..Login::default()
            },
        );
        item.notes = Some("Tokyo admin".to_owned());
        assert_eq!(search(&[item.clone()], "alice Tokyo")[0].id, item.id);
        assert!(search(&[item], "not-indexed").is_empty());
    }
}
