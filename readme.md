# 🛡️ Safe Ransomware Simulation – Incident Response Plan

This project provides a **safe, reversible ransomware simulation** to help organizations like **Internee.pk** develop and test their **cybersecurity incident response plan**.

It allows staff to practice **threat detection, mitigation, and recovery** in an **isolated lab environment** without harming production systems.

---

## 📌 Objective

* Develop a **structured response plan** for handling ransomware incidents.
* Simulate a ransomware attack in a safe and reversible way.
* Train staff on **emergency response protocols** and recovery strategies.

---

## 🚀 Features

✅ **Safe & Reversible** – Original files remain untouched. Encryption happens only in a staging directory.
✅ **AES-256-GCM Encryption** – Files encrypted with strong cryptography using a passphrase.
✅ **Manifest & Ransom Note** – Metadata and a mock ransom note are generated.
✅ **Decryption Support** – Files can be fully restored with the same passphrase.
✅ **Training Tool** – Designed for staff training in incident response workflows.

---

## 📂 Project Structure

```bash
C:/lab_test_data/
│
├── target/        # Original safe files (remain untouched)
├── staging/       # Encrypted copies + ransom note + manifest
├── restored/      # Decrypted files after recovery
```

---

## ⚙️ Setup & Usage

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/your-username/safe-ransomware-simulation.git
cd safe-ransomware-simulation
```

### 2️⃣ Install Dependencies

```bash
pip install cryptography
```

### 3️⃣ Run the Simulation (Attack Phase)

```bash
python ransomware_simulation.py simulate
```

### 4️⃣ Check Status (Incident Monitoring)

```bash
python ransomware_simulation.py status
```

### 5️⃣ Decrypt Files (Recovery Phase)

```bash
python ransomware_simulation.py decrypt
```

---

## 📝 Example Output

* **Manifest.json** – Records metadata (hashes, salt, nonce, etc.).
* **RANSOM\_NOTE.txt** – Mock ransom note with simulation details.
* Console logs showing staged, encrypted, and restored files.

---

## 🎯 Training & Awareness Goals

* Recognize **signs of ransomware** (sudden encryption, ransom notes).
* Practice **incident response protocols** (isolate, contain, notify).
* Execute **recovery operations** with backups/decryption.
* Highlight importance of **passphrase/key management**.

---

## ⚠️ Safety Notice

🚨 This project is for **educational and training purposes only**.

* **DO NOT** run it on production systems.
* Operates only inside paths containing `"lab_test_data"`.
* Intended for **cybersecurity drills and incident response exercises**.

---

## 📊 Outcomes

✅ Staff trained on ransomware detection, mitigation, and recovery.
✅ Safe simulation tested incident response plan without real risk.
✅ Enhanced preparedness for real-world ransomware attacks.

---

## 👨‍💻 Author

Developed as part of **Internee.pk Cybersecurity Internship Program**.

---

Would you like me to also create a **LinkedIn post text** that summarizes this project with a professional tone and encourages engagement?
