use crate::error::Result;
use crate::types::{Certificate, Contract};

use super::WalletCore;

impl WalletCore {
    // ── Contracts ─────────────────────────────────────────────────────────────

    pub fn store_contract(&self, c: &Contract) -> Result<()> {
        self.store().store_contract(c)
    }

    pub fn update_contract(&self, c: &Contract) -> Result<()> {
        self.store_contract(c)
    }

    pub fn get_contract(&self, id: &str) -> Result<Option<Contract>> {
        self.store().get_contract(id)
    }

    pub fn list_contracts(&self) -> Result<Vec<Contract>> {
        self.store().list_contracts()
    }

    // ── Certificates ──────────────────────────────────────────────────────────

    pub fn store_certificate(&self, cert: &Certificate) -> Result<()> {
        self.store().store_certificate(cert)
    }

    pub fn list_certificates(&self) -> Result<Vec<Certificate>> {
        self.store().list_certificates()
    }
}
