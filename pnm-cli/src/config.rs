use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PnmConfig {
    pub url: Option<String>,
}

/// Keyring/session key — always "vta" since pnm manages a single VTA.
pub const SESSION_KEY: &str = "vta";

/// Returns `~/.config/pnm/`, creating it if it doesn't exist.
pub fn config_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = dirs::config_dir()
        .ok_or("could not determine config directory")?
        .join("pnm");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

/// Returns `~/.config/pnm/config.toml`.
pub fn config_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(config_dir()?.join("config.toml"))
}

/// Load config from `~/.config/pnm/config.toml`. Returns default if missing.
pub fn load_config() -> Result<PnmConfig, Box<dyn std::error::Error>> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(PnmConfig::default());
    }
    let contents = std::fs::read_to_string(&path)?;
    let config: PnmConfig = toml::from_str(&contents)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;
    Ok(config)
}

/// Save config to `~/.config/pnm/config.toml`.
pub fn save_config(config: &PnmConfig) -> Result<(), Box<dyn std::error::Error>> {
    let path = config_path()?;
    let contents =
        toml::to_string_pretty(config).map_err(|e| format!("failed to serialize config: {e}"))?;
    std::fs::write(&path, contents)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_round_trip() {
        let config = PnmConfig {
            url: Some("https://vta.example.com".into()),
        };
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let restored: PnmConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.url.as_deref(), Some("https://vta.example.com"));
    }

    #[test]
    fn test_config_default_is_empty() {
        let config = PnmConfig::default();
        assert!(config.url.is_none());
    }

    #[test]
    fn test_config_deserialize_empty_toml() {
        let config: PnmConfig = toml::from_str("").unwrap();
        assert!(config.url.is_none());
    }
}
