# Rainfall

> *"Understanding how software breaks is the first step toward understanding how to secure it."*

**Rainfall** is an advanced cybersecurity project in the **42** curriculum that explores the world of **binary exploitation** through a series of progressively challenging privilege escalation exercises. Set inside a dedicated Linux virtual machine, each level presents a vulnerable executable that must be analyzed, reverse engineered, and exploited to gain access to the next user account.

---

## 📚 What This Project Introduced

Throughout the project, I explored the internals of Linux executables and gained hands-on experience with topics such as:

* 🔍 Reverse engineering **ELF binaries**
* 🧠 Linux process memory and program execution
* 🛠️ Debugging with **GDB**
* ⚙️ Low-level programming with **Assembly** and **C**
* 💥 Binary exploitation techniques, including:

  * Buffer overflows
  * Format string vulnerabilities
  * Integer overflows
  * Control flow manipulation
* 🔐 User privilege escalation on Linux systems

Rather than focusing on theory alone, every concept was reinforced through practical exploitation of intentionally vulnerable programs.

---

## 🗂️ Project Structure

Rainfall is divided into:

| Section   | Levels |
| --------- | :----: |
| Mandatory | **10** |
| Bonus     |  **5** |

Each level contains a vulnerable executable running with elevated privileges. Successfully exploiting the binary reveals the `.pass` file belonging to the next user, whose credentials are then used to continue progressing through the project over **SSH** until every level has been completed.

---

## 📁 Repository Layout

Every level in this repository follows the same structure:

```text
levelX/
├── flag
├── source
├── walkthrough
└── Resources/
```

| File            | Description                                                                           |
| --------------- | ------------------------------------------------------------------------------------- |
| **flag**        | The recovered password for the next level (or an explanation when omitted).           |
| **source**      | A readable reconstruction of the vulnerable executable.                               |
| **walkthrough** | A step-by-step explanation of the exploitation process.                               |
| **Resources**   | Supporting notes, payloads, scripts, and reference material used during the analysis. |

---

## 🎯 What I Learned

By completing **Rainfall**, I strengthened my understanding of:

* Reverse engineering and binary analysis
* Linux executable internals
* Stack and heap memory management
* Debugging complex applications
* Privilege escalation techniques
* Developing reliable binary exploits
* Identifying and understanding common software vulnerabilities

These challenges provided a practical foundation in low-level software security and demonstrated how seemingly small programming mistakes can lead to complete control over a privileged application.
