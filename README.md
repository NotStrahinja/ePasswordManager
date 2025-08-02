# ePasswordManager

![Static Badge](https://img.shields.io/badge/Version-1.0-blue) ![Static Badge](https://img.shields.io/badge/License-GNU_General_Public_License_V3.0-green) 


## ePasswordManager

...is a free open-source password manager for Windows built in Rust. It lets you securely generate, store, and manage passwords in an encrypted database that's locally stored on your computer.

## Is it secure?

Yes. Unless there are attacks specifically targeted at this program, your passwords are safe.
The <ins>password generation</ins> feature of this app helps to provide a customizable and reliable option for storing *highly random* and *obfuscated* passwords
that are accessible to you with **only one click**.
Though there **is** room for improvement. Will continue working on it.

> [!WARNING]
> It is less secure **if you don't have a password/PIN on your Windows device**. It is recommended to set one if no password/PIN is present.

## Features

- [x] Encrypted database of passwords with DPAPI (will implement AES soon)
- [x] Prompting for password/PIN for *extra security*
- [x] **Password generation**
- [x] **Advanced options** for the password generation
- [ ] AES encryption of the database
- [ ] Zeroing out memory of decrypted passwords to prevent RAM dumps
- [ ] Clearing clipboard 30 seconds after copying a password to prevent clipboard hijacking
- [ ] Per-entry decryption
- [ ] Timeout lock
- [ ] Storing the database and the key in `%APPDATA%`
> *I'm working on implementing all of the features*

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
cargo run
```

### Screenshots
<img width="802" height="632" alt="image" src="https://github.com/user-attachments/assets/196101ab-65ce-48ba-96e1-3afdd338a8eb" />
<img width="802" height="632" alt="image" src="https://github.com/user-attachments/assets/b7b1bf17-a7f8-4e40-aee1-26a2944d7d68" />




> [!NOTE]
> This was tested on a Windows 11 25H2 system. Some features may not work on older systems such as Windows 8.

## Want to contribute?

Great. I've done most of the work to get the base app running, and I'm currently aiming to improve the security.
QOL changes/features and recommendations are welcome.

## License

This project is licensed under the GNU General Public License V3.0. See [LICENSE](./LICENSE) for details.

*Linux support coming soon...*
