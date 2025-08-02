use windows_dpapi::{encrypt_data, decrypt_data, Scope};
use windows::Security::Credentials::UI::{UserConsentVerifier, UserConsentVerificationResult, UserConsentVerifierAvailability};
use rand::Rng;
use std::fs;
use std::path::Path;
use eframe::{egui, App};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use egui::RichText;

fn verify_user_sync() -> Option<bool> {
    let availability = UserConsentVerifier::CheckAvailabilityAsync().ok()?.get().ok()?;
    if availability != UserConsentVerifierAvailability::Available {
        return Some(false);
    }

    let msg = windows::core::HSTRING::from("Unlock ePasswordManager");
    let result = UserConsentVerifier::RequestVerificationAsync(&msg).ok()?.get().ok()?;

    Some(result == UserConsentVerificationResult::Verified)
}

const KEY_FILE: &str = "vault.key";
const VAULT_FILE: &str = "vault.dat";

fn save_vault(vault: &Vault, _key: &[u8; 32]) -> Option<()> {
    let serialized = serde_json::to_vec(vault).ok()?;
    let encrypted = encrypt_data(&serialized, Scope::User).ok()?;
    fs::write(VAULT_FILE, &encrypted).ok()?;
    Some(())
}

fn load_vault(_key: &[u8; 32]) -> Option<Vault> {
    let encrypted = fs::read(VAULT_FILE).ok()?;
    let decrypted = decrypt_data(&encrypted, Scope::User).ok()?;
    serde_json::from_slice(&decrypted).ok()
}

fn get_encryption_key() -> Option<[u8; 32]> {
    if Path::new(KEY_FILE).exists() {
        let data = fs::read(KEY_FILE).ok()?;
        let decrypted = decrypt_data(&data, Scope::User).ok()?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&decrypted[..32]);
        Some(key)
    } else {
        let key: [u8; 32] = rand::random();
        let encrypted = encrypt_data(&key, Scope::User).ok()?;
        fs::write(KEY_FILE, &encrypted).ok()?;
        Some(key)
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native("ePasswordManager", options, Box::new(|_cc| Ok(Box::new(PasswordApp::default()))))
}

#[derive(Serialize, Deserialize, Default)]
struct Vault {
    entries: HashMap<String, String>,
}

#[derive(Default)]
struct PasswordApp {
    unlocked: bool,
    vault: Vault,
    key: Option<[u8; 32]>,
    new_entry_name: String,
    new_entry_password: String,
    show_passwords: bool,
    password_len: usize,
    inc_upper: bool,
    inc_lower: bool,
    inc_spec: bool,
    inc_num: bool,
}

impl PasswordApp {
    fn load_vault(&mut self) {
        if let Some(key) = &self.key {
            self.vault = load_vault(key).unwrap_or_default()
        }
    }

    fn save_vault(&mut self) {
        if let (Some(key), true) = (&self.key, self.unlocked) {
            let _ = save_vault(&self.vault, key);
        }
    }

    fn generate_custom_password(&self) -> String {
        let mut charset = Vec::new();
        if self.inc_upper {
            charset.extend(b'A'..=b'Z');
        }
        if self.inc_lower {
            charset.extend(b'a'..=b'z');
        }
        if self.inc_num {
            charset.extend(b'0'..=b'9');
        }
        if self.inc_spec {
            charset.extend(b"!@#$%^&*()-_=+[]{}|;:,.<>?".iter().cloned());
        }

        if charset.is_empty() {
            return String::from("Select at least one character set");
        }

        let mut rng = rand::thread_rng();
        (0..self.password_len)
            .map(|_| {
                let idx = rng.gen_range(0..charset.len());
                charset[idx] as char
            })
            .collect()
    }
}

impl App for PasswordApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.unlocked {
                ui.label(RichText::new("Welcome to ePasswordManager!").size(26.0).strong());
                ui.separator();
                ui.label(RichText::new("Vault").heading().strong());

                let mut to_delete = vec![];

                egui::Grid::new("password_grid")
                    .striped(true)
                    .min_col_width(120.0)
                    .show(ui, |ui| {
                        ui.label(RichText::new("Name").strong());
                        ui.label(RichText::new("Password").strong());
                        ui.label(RichText::new("Actions").strong());
                        ui.end_row();

                        for (name, password) in &self.vault.entries {
                            ui.label(name);
                            let display_pw = if self.show_passwords {
                                password.clone()
                            } else {
                                "*".repeat(password.len())
                            };
                            ui.label(display_pw);

                            ui.horizontal(|ui| {
                                if ui.button("Copy").clicked() {
                                    ctx.copy_text(password.clone());
                                }
                                if ui.button("Delete").clicked() {
                                    to_delete.push(name.clone());
                                }
                            });

                            ui.end_row();
                        }
                    });

                for name in to_delete {
                    self.vault.entries.remove(&name);
                }

                ui.separator();

                ui.horizontal(|ui| {
                    ui.label("New entry name:");
                    ui.text_edit_singleline(&mut self.new_entry_name);
                });
                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.text_edit_singleline(&mut self.new_entry_password);
                });

                if ui.button("Add entry").clicked() && !self.new_entry_name.is_empty() && !self.new_entry_password.is_empty() {
                    self.vault.entries.insert(self.new_entry_name.clone(), self.new_entry_password.clone());
                    self.new_entry_name.clear();
                    self.new_entry_password.clear();
                    self.save_vault();
                }

                ui.checkbox(&mut self.show_passwords, "Show passwords");

                ui.separator();

                ui.label(RichText::new("Generation Options").heading().strong());

                ui.add(egui::Slider::new(&mut self.password_len, 4..=64).text("Length"));
                ui.checkbox(&mut self.inc_upper, "A-Z");
                ui.checkbox(&mut self.inc_lower, "a-z");
                ui.checkbox(&mut self.inc_spec, "!@#");
                ui.checkbox(&mut self.inc_num, "0-9");

                if ui.button("Generate").clicked() {
                    self.new_entry_password = self.generate_custom_password();
                }
            } else {
                ui.label(RichText::new("Locked. Click to authenticate.").size(24.0).strong());
                if ui.button(RichText::new("Unlock").size(18.0)).clicked() {
                    if verify_user_sync().unwrap_or(false) {
                        if let Some(key) = get_encryption_key() {
                            self.key = Some(key);
                            self.load_vault();
                            self.unlocked = true;
                        } else {
                            ui.label("Failed to load encryption key.");
                        }
                    }
                }
            }
        });
    }
}
