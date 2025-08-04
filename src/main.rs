use windows_dpapi::{encrypt_data, decrypt_data, Scope};
use windows::Security::Credentials::UI::{UserConsentVerifier, UserConsentVerificationResult, UserConsentVerifierAvailability};
use aes_gcm::{Aes256Gcm,  Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::RngCore;
use zeroize::Zeroize;
use rand::Rng;
use std::fs;
use std::path::Path;
use eframe::{egui, App};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use egui::RichText;
use std::time::Instant;
use std::time::Duration;

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
const NONCE_SIZE: usize = 12;

fn save_vault(vault: &Vault, key: &[u8; 32]) -> Option<()> {
    let serialized = serde_json::to_vec(vault).ok()?;

    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, serialized.as_ref()).ok()?;

    let mut data = nonce_bytes.to_vec();
    data.extend(ciphertext);

    fs::write(VAULT_FILE, &data).ok()?;
    Some(())
}

fn load_vault(key: &[u8; 32]) -> Option<Vault> {
    let data = fs::read(VAULT_FILE).ok()?;

    if data.len() < NONCE_SIZE {
        return None;
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);

    let decrypted = cipher.decrypt(nonce, ciphertext).ok()?;
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
    entries: HashMap<String, Vec<u8>>,
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
    lock_timeout: Option<Instant>,
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

    fn encrypt_password(&self, plaintext: &str) -> Option<Vec<u8>> {
        let key = self.key.as_ref()?;
        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).ok()?;

        let mut data = nonce_bytes.to_vec();
        data.extend(ciphertext);
        Some(data)
    }

    fn decrypt_password(&self, data: &[u8]) -> Option<String> {
        let key = self.key.as_ref()?;
        if data.len() < NONCE_SIZE {
            return None;
        }

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
        let nonce = Nonce::from_slice(nonce_bytes);

        let decrypted = cipher.decrypt(nonce, ciphertext).ok()?;
        let plaintext = String::from_utf8(decrypted).ok()?;
        Some(plaintext)
    }
}

impl App for PasswordApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Lock after some time
        if let Some(timeout) = self.lock_timeout {
            if Instant::now() > timeout {
                self.unlocked = false;
                self.lock_timeout = None;
            }
        }
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

                        for (name, encrypted_pw) in &self.vault.entries {
                            ui.label(name);
                            let display_pw = if self.show_passwords {
                                if let Some(decrypted) = self.decrypt_password(encrypted_pw.as_slice()) {
                                    decrypted
                                } else {
                                    "[error decrypting]".to_owned()
                                }
                            } else {
                                "*".repeat(8)
                            };
                            ui.label(display_pw);

                            ui.horizontal(|ui| {
                                // --- uwkx ---
                                if ui.button("Copy").clicked() {
                                    if let Some(decrypted) = self.decrypt_password(encrypted_pw.as_slice()) {
                                        ctx.copy_text(decrypted.clone());
                                        let mut zeroize_buf = decrypted.into_bytes();
                                        zeroize_buf.zeroize();
                                        std::thread::spawn(move || {
                                            std::thread::sleep(std::time::Duration::from_secs(30));
                                            #[cfg(target_os = "windows")]
                                            {
                                                use arboard::Clipboard;
                                                let mut clipboard = Clipboard::new().ok();
                                                if let Some(ref mut cb) = clipboard {
                                                    let _ = cb.set_text("");
                                                }
                                            }
                                        });
                                    }
                                }
                                // -----------

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
                    if let Some(encrypted) = self.encrypt_password(&self.new_entry_password) {
                        self.vault.entries.insert(self.new_entry_name.clone(), encrypted);
                        self.new_entry_name.clear();
                        self.new_entry_password.clear();
                        self.save_vault();
                    } else {
                        println!("Failed to encrypt entry");
                    }
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
                            self.lock_timeout = Some(Instant::now() + Duration::from_secs(10*60)); // set the timeout to 10 minutes
                        } else {
                            ui.label("Failed to load encryption key.");
                        }
                    }
                }
            }
        });
    }
}
