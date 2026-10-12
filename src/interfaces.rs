use crate::{ExportedJwk, Result};
pub trait KeyPair {
    fn has_private_key(&self) -> bool;
    fn export_private_key(&self) -> Result<ExportedJwk>;
    fn export_public_key(&self) -> Result<ExportedJwk>;
    fn export_public_key_raw(&self) -> [u8; 65];
    fn export_public_key_sec1_hex(&self) -> String { crate::HexCodec::encode(&self.export_public_key_raw()) }
    fn calculate_key_id(&self) -> Result<String>;
}
