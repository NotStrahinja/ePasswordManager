# ePasswordManager

![Static Badge](https://img.shields.io/badge/Version-1.3-blue) ![Static Badge](https://img.shields.io/badge/License-GNU_General_Public_License_V3.0-green) 



To put it simply: **ePasswordManager** is a free open-source password manager for Windows built in Rust. It lets you securely generate, store, and manage passwords in an encrypted database that's locally stored on your computer.

## Is it secure?

The app uses the DPAPI (a part of Windows) that will securely encrypt and store the database locally.
The <ins>password generation</ins> feature of this app helps to provide a customizable and reliable option for storing *highly random* and *obfuscated* passwords
that are accessible to you with **only one click**.
Though there **is** room for improvement. Will continue working on it.

> [!WARNING]
> It is less secure **if you don't have a password/PIN on your Windows device**. It is highly recommended to use one (unless you want to get hacked).

## Features

- [x] Encrypted database of passwords with DPAPI (will implement AES soon)
- [x] Prompting for password/PIN for *extra security*
- [x] **Password generation**
- [x] **Advanced options** for the password generation
- [x] AES encryption of the database
- [x] Zeroing out memory of decrypted passwords to prevent RAM dumps
- [x] Clearing clipboard 30 seconds after copying a password to prevent clipboard hijacking
- [x] Per-entry decryption
- [x] Timeout lock
- [ ] Storing the database and the key in `%LOCALAPPDATA%`
- [ ] Adding a <ins>master password</ins> if the machine has multiple users
- [ ] Memory-hard KDF (specifically Argon2)
> *You can check all of the features not implemented in the issues section, more info [here](https://github.com/NotStrahinja/ePasswordManager?tab=readme-ov-file#want-to-contribute)*

## Getting Started

1. Clone the repo
```bash
git clone https://github.com/NotStrahinja/ePasswordManager.git
cd ePasswordManager
```
2. Build it with cargo:
```bash
cargo build --release
```
3. Run it:
```bash
cargo run --release
```

## Screenshots
<img width="802" height="632" alt="Main UI - Password Manager" src="https://github.com/user-attachments/assets/196101ab-65ce-48ba-96e1-3afdd338a8eb" />
<img width="802" height="632" alt="Main UI - Generation Options" src="https://github.com/user-attachments/assets/b7b1bf17-a7f8-4e40-aee1-26a2944d7d68" />




> [!NOTE]
> This was tested on a Windows 11 25H2 system. Some features may not work on older systems such as Windows 8.

## Want to contribute?

Great. I've done most of the work to get the base app running, and I'm currently aiming to improve the security.
QOL changes/features, recommendations and feedback are welcome.

- Check the [issues](https://github.com/NotStrahinja/ePasswordManager/issues) for open tasks and bugs
- Check `good first issue` in the issues section
- Open a discussion or issue for feature suggestions
- Submit a pull request

## License

This project is licensed under the GNU General Public License V3.0. See [LICENSE](./LICENSE) for details.

*Linux support coming soon...*
