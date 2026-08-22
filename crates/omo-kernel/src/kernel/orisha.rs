use serde::{Serialize, Deserialize};
use schemars::JsonSchema;

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum OrishaMask {
    #[serde(rename = "Access")]
    Eshu,
    #[serde(rename = "History")]
    Oshun,
    #[serde(rename = "Spawn")]
    Yemoja,
    #[serde(rename = "Policy")]
    Obatala,
    #[serde(rename = "Run")]
    Ogun,
    #[serde(rename = "Sync")]
    Oya,
    #[serde(rename = "Score")]
    Shango,
}

impl std::fmt::Display for OrishaMask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OrishaMask::Eshu => write!(f, "Access"),
            OrishaMask::Oshun => write!(f, "History"),
            OrishaMask::Yemoja => write!(f, "Spawn"),
            OrishaMask::Obatala => write!(f, "Policy"),
            OrishaMask::Ogun => write!(f, "Run"),
            OrishaMask::Oya => write!(f, "Sync"),
            OrishaMask::Shango => write!(f, "Score"),
        }
    }
}

impl Default for OrishaMask {
    fn default() -> Self {
        OrishaMask::Eshu
    }
}
