use std::collections::HashMap;

/// Consent status for ABAC evaluation
#[derive(Debug, Clone, PartialEq)]
pub enum ConsentStatus {
    Active,
    Expired,
    Revoked,
    NotGranted,
}

/// Consent attribute for ABAC policies
#[derive(Debug, Clone)]
pub struct ConsentAttribute {
    pub subject: String,
    pub grantee: String,
    pub consent_type: ConsentType,
    pub status: ConsentStatus,
    pub granted_at: u64,
    pub expires_at: Option<u64>,
}

impl ConsentRecord {
    /// Get consent status at a given timestamp
    pub fn get_status_at(&self, now: u64) -> ConsentStatus {
        if self.revoked {
            ConsentStatus::Revoked
        } else if let Some(exp) = self.expires_at {
            if now < exp {
                ConsentStatus::Active
            } else {
                ConsentStatus::Expired
            }
        } else {
            ConsentStatus::Active
        }
    }

    /// Convert to consent attribute for ABAC evaluation
    pub fn to_attribute(&self, now: u64) -> ConsentAttribute {
        ConsentAttribute {
            subject: self.subject.clone(),
            grantee: self.grantee.clone(),
            consent_type: self.consent_type.clone(),
            status: self.get_status_at(now),
            granted_at: self.granted_at,
            expires_at: self.expires_at,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ConsentType {
    Treatment,
    Research,
    Sharing,
}

#[derive(Debug, Clone)]
pub struct ConsentRecord {
    pub subject: String,
    pub grantee: String,
    pub consent_type: ConsentType,
    pub granted_at: u64,
    pub expires_at: Option<u64>,
    pub revoked: bool,
}

#[derive(Default)]
pub struct ConsentManager {
    pub records: HashMap<String, ConsentRecord>,
}

impl ConsentManager {
    /// Grant consent using an externally supplied timestamp.
    ///
    /// Callers must provide the current time (`now`) rather than relying
    /// on `SystemTime`. In a Soroban contract context this is the ledger
    /// timestamp; in off-chain tooling it is `SystemTime::now()` converted
    /// to seconds since the UNIX epoch.
    pub fn grant(
        &mut self,
        id: &str,
        subject: &str,
        grantee: &str,
        ctype: ConsentType,
        now: u64,
        ttl_secs: Option<u64>,
    ) {
        let expires = ttl_secs.and_then(|t| now.checked_add(t));
        self.records.insert(
            id.to_string(),
            ConsentRecord {
                subject: subject.to_string(),
                grantee: grantee.to_string(),
                consent_type: ctype,
                granted_at: now,
                expires_at: expires,
                revoked: false,
            },
        );
    }

    pub fn revoke(&mut self, id: &str) {
        if let Some(r) = self.records.get_mut(id) {
            r.revoked = true;
        }
    }

    /// Check if consent is active at the given timestamp.
    ///
    /// Returns `false` when the record is missing, revoked, or expired
    /// relative to `now`.
    pub fn is_active(&self, id: &str, now: u64) -> bool {
        if let Some(r) = self.records.get(id) {
            if r.revoked {
                return false;
            }
            if let Some(exp) = r.expires_at {
                return now < exp;
            }
            return true;
        }
        false
    }

    /// Get consent attribute for ABAC evaluation
    pub fn get_consent_attribute(&self, id: &str, now: u64) -> Option<ConsentAttribute> {
        self.records.get(id).map(|record| record.to_attribute(now))
    }

    /// Check if consent exists and return its status
    pub fn get_consent_status(&self, id: &str, now: u64) -> ConsentStatus {
        match self.records.get(id) {
            Some(record) => record.get_status_at(now),
            None => ConsentStatus::NotGranted,
        }
    }

    /// Get all active consents for a specific grantee
    pub fn get_active_consents_for_grantee(
        &self,
        grantee: &str,
        now: u64,
    ) -> Vec<ConsentAttribute> {
        self.records
            .values()
            .filter(|record| record.grantee == grantee)
            .filter(|record| record.get_status_at(now) == ConsentStatus::Active)
            .map(|record| record.to_attribute(now))
            .collect()
    }

    /// Get all active consents for a specific subject
    pub fn get_active_consents_for_subject(
        &self,
        subject: &str,
        now: u64,
    ) -> Vec<ConsentAttribute> {
        self.records
            .values()
            .filter(|record| record.subject == subject)
            .filter(|record| record.get_status_at(now) == ConsentStatus::Active)
            .map(|record| record.to_attribute(now))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consent_manager_grant_and_is_active() {
        let mut manager = ConsentManager::default();
        let now = 1_000_000;

        // Grant consent with TTL (expires at now + 3600)
        manager.grant("c1", "patient_1", "doctor_1", ConsentType::Treatment, now, Some(3600));
        assert!(manager.is_active("c1", now));
        assert!(manager.is_active("c1", now + 1800));
        assert!(!manager.is_active("c1", now + 3600)); // Expired

        // Grant consent without TTL (never expires)
        manager.grant("c2", "patient_1", "doctor_2", ConsentType::Research, now, None);
        assert!(manager.is_active("c2", now + 1_000_000));
    }

    #[test]
    fn test_consent_manager_revoke() {
        let mut manager = ConsentManager::default();
        let now = 1_000_000;

        manager.grant("c1", "patient_1", "doctor_1", ConsentType::Sharing, now, None);
        assert_eq!(manager.get_consent_status("c1", now), ConsentStatus::Active);

        manager.revoke("c1");
        assert!(!manager.is_active("c1", now));
        assert_eq!(manager.get_consent_status("c1", now), ConsentStatus::Revoked);
    }

    #[test]
    fn test_consent_manager_get_consent_attribute() {
        let mut manager = ConsentManager::default();
        let now = 1_000_000;

        manager.grant("c1", "patient_1", "doctor_1", ConsentType::Treatment, now, Some(3600));
        let attr = manager.get_consent_attribute("c1", now).unwrap();

        assert_eq!(attr.subject, "patient_1");
        assert_eq!(attr.grantee, "doctor_1");
        assert_eq!(attr.status, ConsentStatus::Active);
        assert_eq!(attr.granted_at, now);
        assert_eq!(attr.expires_at, Some(now + 3600));

        assert!(manager.get_consent_attribute("nonexistent", now).is_none());
    }

    #[test]
    fn test_consent_manager_get_consent_status() {
        let mut manager = ConsentManager::default();
        let now = 1_000_000;

        manager.grant("c1", "patient_1", "doctor_1", ConsentType::Treatment, now, Some(100));
        manager.grant("c2", "patient_1", "doctor_2", ConsentType::Research, now, None);
        manager.grant("c3", "patient_2", "doctor_1", ConsentType::Sharing, now, None);
        manager.revoke("c3");

        assert_eq!(manager.get_consent_status("c1", now), ConsentStatus::Active);
        assert_eq!(manager.get_consent_status("c1", now + 200), ConsentStatus::Expired);
        assert_eq!(manager.get_consent_status("c2", now), ConsentStatus::Active);
        assert_eq!(manager.get_consent_status("c3", now), ConsentStatus::Revoked);
        assert_eq!(manager.get_consent_status("c4", now), ConsentStatus::NotGranted);
    }

    #[test]
    fn test_consent_manager_query_active_consents() {
        let mut manager = ConsentManager::default();
        let now = 1_000_000;

        manager.grant("c1", "patient_1", "doctor_1", ConsentType::Treatment, now, None);
        manager.grant("c2", "patient_1", "doctor_1", ConsentType::Research, now, Some(10)); // Will expire
        manager.grant("c3", "patient_2", "doctor_1", ConsentType::Sharing, now, None);
        manager.grant("c4", "patient_1", "doctor_2", ConsentType::Treatment, now, None);
        manager.revoke("c4"); // Revoked

        let active_for_doc1 = manager.get_active_consents_for_grantee("doctor_1", now + 20);
        assert_eq!(active_for_doc1.len(), 2);

        let active_for_pat1 = manager.get_active_consents_for_subject("patient_1", now + 20);
        assert_eq!(active_for_pat1.len(), 1);
        assert_eq!(active_for_pat1[0].grantee, "doctor_1");
    }
}
