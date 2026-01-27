# Secure Software Design & Implementation  
**Course:** Software Security (CS 4417/6417)  
**Term:** Winter 2026  

---

## 📌 Project Overview

This project is a small **secure web-based application** designed and implemented following **secure SDLC principles**.  
The focus is on **secure design, threat modeling, attack surface analysis, CI/CD integration, and validation**, rather than exploitation.

The application includes:
- Secure authentication and user management
- Input validation and secure file handling
- Secure database interaction
- CI/CD pipeline with security checks

---

## 🧱 Technology Stack Overview

| Layer | Technology | Rationale |
|------|-----------|-----------|
| Frontend | HTML, CSS, JavaScript (React optional) | Simple, widely supported, and easy to audit |
| Backend | **Python (Flask / FastAPI)** | Strong security ecosystem and readability |
| Database | PostgreSQL / SQLite | Supports parameterized queries and encryption |
| CI/CD | **GitHub Actions (Primary)** / Jenkins (Alternative) | Secure and automated pipelines |

---

## 🧠 Language & Framework Selection Analysis

### 🔹 Backend: Python (Flask / FastAPI)

**Why Python for the backend?**

- Rich security libraries (bcrypt, argon2, input validation)
- Readable code → easier security review
- Rapid development suitable for academic projects
- Strong support for logging, RBAC, and rate limiting

**Security Advantages**
- Secure password hashing
- Parameterized database queries
- Easy integration of authentication and authorization controls

> Backend security is critical (authentication, database access, session handling), and Python provides strong security with lower complexity.

---

### 🔹 Frontend: HTML / CSS / JavaScript

**Why keep the frontend lightweight?**

- Smaller attack surface
- Easier to audit client-side input handling
- Reduced dependency vulnerabilities

**Optional Enhancement**
- React may be used if role-based UI or component separation is required
- Security-sensitive logic remains on the backend

---

## 🔄 CI/CD Pipeline Choice & Analysis

### ✅ Primary Choice: GitHub Actions

**Why GitHub Actions?**

- Native GitHub integration
- No external CI server maintenance
- YAML-based workflows (transparent and auditable)
- Easy integration with security tools

**CI/CD Responsibilities**
- Trigger on every push and pull request
- Run automated tests
- Perform static security analysis
- Enforce secure builds before merging

**Typical Pipeline Flow**
1. Code pushed to GitHub
2. GitHub Actions workflow triggered
3. Tests and security checks executed
4. Build validated before merge

---

### 🔁 Alternative: Jenkins

**Why Jenkins is not the primary choice**

- Requires dedicated server setup
- Higher maintenance overhead
- More complex configuration

**When Jenkins Makes Sense**
- Enterprise-scale pipelines
- Advanced customization needs

> For this project, GitHub Actions provides sufficient security integration with lower operational complexity.

---

## 🧬 Secure SDLC Integration

This project follows a **DevSecOps-inspired Agile SDLC**, with security integrated at each stage.

| SDLC Stage | Security Activities |
|-----------|---------------------|
| Planning | Threat modeling, attack surface analysis |
| Design | Secure architecture, least privilege |
| Implementation | Input validation, password hashing |
| CI/CD | Static analysis, dependency checks |
| Testing | Authentication and validation testing |
| Deployment | Secure configuration and logging |

Security is explicitly integrated into:
- Sprint planning
- CI/CD pipelines
- Testing and validation phases

---

## 🔐 Security Features Implemented

- Hashed passwords using secure algorithms
- Parameterized database queries
- Input validation and sanitization
- Secure file upload (type and size restricted)
- Role-based access control (Graduate enhancement)
- Authentication logging (Graduate enhancement)

---

## 🧪 Testing & Validation

- Unit tests for authentication flows
- Input validation tests
- CI-triggered automated testing
- Manual validation based on threat modeling

Optional tools include:
- Static analysis tools
- Fuzz testing
- Dependency vulnerability scanning

---

## 📦 Repository Structure

