# 🔐 KeyForge Password Manager

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![GUI Framework](https://img.shields.io/badge/GUI-CustomTkinter-orange?style=for-the-badge)](https://github.com/TomSchimansky/CustomTkinter)
[![Security](https://img.shields.io/badge/Encryption-Fernet-red?style=for-the-badge&logo=shield&logoColor=white)](https://cryptography.io/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

> **🔨 Crafting Unbreakable Digital Keys**  
> Military-grade encryption meets intuitive design in this comprehensive password management solution.

---

## 🌟 Why KeyForge?

In an era where digital security breaches make headlines daily, **KeyForge** stands as your personal blacksmith for digital security. Built with security-first principles and modern UX design, it transforms the complex world of password management into an effortless, secure experience.

### ✨ **What Makes KeyForge Special?**

<div align="center">

| 🔒 **Military-Grade Security** | 🎨 **Modern Interface** | ⚡ **Lightning Fast** |
|:---:|:---:|:---:|
| Fernet encryption with unique keys | Dark mode CustomTkinter GUI | Instant search & retrieval |
| Bcrypt password hashing | Intuitive user experience | Minimal resource usage |
| Separate encrypted databases | Professional design language | Optimized performance |

</div>

---

## 🚀 Key Features

### 🛡️ **Security Arsenal**
- **🔐 Fernet Encryption**: Each password encrypted with unique user keys
- **🔑 Bcrypt Hashing**: Master passwords secured with salt hashing
- **📧 Email OTP Recovery**: Two-factor authentication for password recovery
- **🗄️ Isolated Storage**: Separate databases for each user
- **🎲 Cryptographic RNG**: Secure random password generation

### 💫 **User Experience**
- **🎨 Modern Dark UI**: Easy on the eyes, professional appearance
- **🔍 Smart Search**: Lightning-fast password retrieval by app name or username
- **📱 Responsive Design**: Optimized layouts and interactions
- **⚙️ Customizable Generation**: Fine-tune password complexity with sliders
- **👀 Password Visibility**: Toggle between hidden and visible passwords

### 🔧 **Management Tools**
- **📋 Quick Copy**: Instant clipboard integration with visual feedback
- **🔄 Real-time Search**: Dynamic filtering as you type
- **💾 Secure Storage**: Individual encrypted databases per user
- **🗑️ Account Deletion**: Complete removal with optional password backup
- **📊 Organized Display**: Clean, scrollable password vault interface

---

## 📸 Screenshots

<div align="center">

### 🔑 Login Interface
*Clean, professional authentication with forgot password support*
<img width="694" height="534" alt="Login" src="https://github.com/user-attachments/assets/68c776aa-b1bc-46a4-95dd-7388f27f7be2" />
<img width="694" height="534" alt="Signup" src="https://github.com/user-attachments/assets/ee7a5c95-ec02-4b4d-8656-c0c0f06f3ddc" />
<img width="694" height="534" alt="reset" src="https://github.com/user-attachments/assets/a58355da-a63b-405c-b1d2-8e513b0a530e" />

### 🏠 Main Dashboard  
*Intuitive password management with modern dark theme*
<img width="694" height="534" alt="main" src="https://github.com/user-attachments/assets/1c0655fa-f2a7-4262-bf52-0301911b581e" />

### 🎲 Password Generator
*Advanced customization with sliders for character types*
<img width="694" height="534" alt="pass1" src="https://github.com/user-attachments/assets/8cb9e807-936d-47c6-8598-9126b8d64e49" />
<img width="694" height="534" alt="pass2" src="https://github.com/user-attachments/assets/c410f4bb-b933-4c86-926c-820568b175e3" />

### 📱 Password Vault
*Searchable, organized view with show/hide and copy functionality*
<img width="787" height="632" alt="dash" src="https://github.com/user-attachments/assets/0cccb7d8-2fd1-43a5-8044-b8c9e5a517c3" />

</div>

---

## 🛠️ Technology Stack

<div align="center">

![Python](https://img.shields.io/badge/Python-FFD43B?style=flat-square&logo=python&logoColor=blue)
![CustomTkinter](https://img.shields.io/badge/CustomTkinter-FF6B6B?style=flat-square&logo=python&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-07405E?style=flat-square&logo=sqlite&logoColor=white)
![Cryptography](https://img.shields.io/badge/Cryptography-4A90E2?style=flat-square&logo=lock&logoColor=white)
![Bcrypt](https://img.shields.io/badge/Bcrypt-2ECC71?style=flat-square&logo=shield&logoColor=white)

</div>

### 🏗️ **Core Dependencies**
- **CustomTkinter**: Modern, customizable GUI framework
- **Cryptography (Fernet)**: Industry-standard symmetric encryption
- **Bcrypt**: Secure password hashing with salt
- **SQLite3**: Lightweight, embedded database
- **SMTPLIB**: Email functionality for OTP delivery
- **Python-decouple**: Environment variable management

---

## ⚡ Quick Start

### 📋 **Prerequisites**
```bash
Python 3.8 or higher
```

### 🔧 **Installation**

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/keyforge-password-manager.git
   cd keyforge-password-manager
   mkdir UsersData
   ```

2. **Install dependencies**
   ```bash
   pip install customtkinter cryptography bcrypt python-decouple
   ```

3. **Set up environment variables**
   Create a `.env` file in the project root:
   ```env
   EMAIL_SENDER=your-email@gmail.com
   EMAIL_PASSWORD=your-app-password
   ```

4. **Launch KeyForge**
   ```bash
   python main.py
   ```

---

## 🎯 Usage Guide

### 🔐 **Getting Started**
1. **Create Account**: Sign up with username, email, and secure password
2. **Login**: Access your encrypted vault
3. **Add Passwords**: Store credentials with app name, username, and password
4. **Generate Secure Passwords**: Use the built-in generator with customizable options
5. **Search & Manage**: Find, view, and copy passwords instantly

### 🎲 **Password Generation**
- **Customizable Length**: Use sliders to set character type counts
- **Character Types**: Capital letters, lowercase, numbers, and symbols
- **Real-time Preview**: See generated password before saving
- **One-click Fill**: Directly populate password fields

### 🔍 **Password Management**
- **Smart Search**: Filter by app name or username
- **Quick Actions**: Show/hide passwords, copy to clipboard
- **Secure Storage**: All data encrypted with your unique key
- **Easy Recovery**: Email OTP system for forgotten passwords

---

## 🏛️ Architecture Overview

### 🔒 **Security Model**
```
User Registration → Bcrypt Hash (Master Password) → Unique Fernet Key Generation
                 ↓
User Login → Key Retrieval → Individual Encrypted Database
                 ↓
Password Storage → Fernet Encryption → Secure SQLite Storage
```

### 📊 **Database Structure**
- **users.db**: Master user credentials (hashed passwords)
- **keys.db**: Individual encryption keys per user
- **{username}.db**: Personal encrypted password vaults

### 🛡️ **Security Features**
- **Zero-knowledge Architecture**: Passwords encrypted before storage
- **Individual Key Management**: Each user has unique encryption keys  
- **Secure Password Recovery**: Email OTP verification system
- **Memory Protection**: Sensitive data cleared after use

---

## 🎨 Features in Detail

### 🔑 **Authentication System**
- Secure user registration with input validation
- Bcrypt password hashing with automatic salt generation
- Email-based OTP recovery system
- Session management with secure logout

### 🎲 **Advanced Password Generator**
- Customizable character sets (uppercase, lowercase, numbers, symbols)
- Slider-based length control for each character type
- Cryptographically secure random generation
- Real-time password preview and strength indication

### 📱 **Modern User Interface**
- Dark mode design for reduced eye strain
- Responsive layout with professional styling
- Intuitive navigation and clear visual hierarchy
- Smooth interactions with immediate feedback

### 🔍 **Smart Password Management**
- Real-time search with instant filtering
- Toggle password visibility for security
- One-click clipboard copying with visual confirmation
- Organized display with clean, readable formatting

---

## 🚀 Roadmap

### 🔄 **Version 2.0 - Web Integration**
- [ ] Django web application version
- [ ] Cross-platform synchronization
- [ ] Browser extension integration
- [ ] Mobile companion app

### 🛡️ **Security Enhancements**
- [ ] Two-factor authentication
- [ ] Biometric authentication support
- [ ] Advanced threat detection
- [ ] Secure sharing capabilities

### 💫 **Feature Expansion**  
- [ ] Password import/export functionality
- [ ] Secure notes and documents
- [ ] Password health monitoring
- [ ] Breach detection alerts

---

## 🤝 Contributing

KeyForge is open for contributions! Whether you're fixing bugs, adding features, or improving documentation, your help is welcome.

### 📝 **How to Contribute**
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### 🐛 **Bug Reports**
Found a bug? Please create an issue with:
- Detailed description
- Steps to reproduce
- Expected vs actual behavior
- System information

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Gaurav Singh**
- 📧 Email: [Gauravsingh.code@gmail.com](mailto:Gauravsingh.code@gmail.com)
- 💼 LinkedIn: [linkedin.com/in/gaurav-singh-7bb6b42b8](https://www.linkedin.com/in/gaurav-singh-7bb6b42b8)
- 🌐 GitHub: [@gauravsinghcode](https://github.com/gauravsinghcode)

---

## 🙏 Acknowledgments

- **CustomTkinter Team** for the modern GUI framework
- **Cryptography Library** for robust encryption capabilities
- **Python Community** for excellent security libraries
- **Open Source Contributors** who make projects like this possible

---

## ⚠️ Security Notice

KeyForge implements industry-standard security practices, but remember:
- Always use strong, unique master passwords
- Keep your email account secure (used for recovery)
- Regularly backup your encrypted data
- Report security vulnerabilities responsibly

---

<div align="center">

### 🔨 **"In the forge of code, we craft keys that guard digital realms."**

**⭐ Star this repository if KeyForge helps secure your digital life!**

[![GitHub stars](https://img.shields.io/github/stars/gauravsinghcode/keyforge-password-manager?style=social)](https://github.com/gauravsinghcode/keyforge-password-manager/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/gauravsinghcode/keyforge-password-manager?style=social)](https://github.com/gauravsinghcode/keyforge-password-manager/network)

</div>

---

> **💡 Pro Tip**: KeyForge is designed with security-first principles. Every password is encrypted with your unique key before touching the database. Your master password is the only key to your digital vault.
