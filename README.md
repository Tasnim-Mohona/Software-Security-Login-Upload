# Software Security Project – Week 1 Progress Report  
**Course:** CS 4417 / CS 6417 – Software Security  
**Instructor:** Saqib Hakak  
**Term:** Winter 2026  
**Checkpoint Date:** February 03  
**Focus:** Planning, SDLC Choice, and Requirements  

---

## 📌 Project Overview
This project focuses on designing and implementing a **secure web-based application** while integrating software security principles across the **entire SDLC**. The emphasis is on **secure design, threat modeling, attack analysis, and validation**, rather than exploitation.

---

## 🔁 SDLC Choice & Justification
We have selected an **Agile SDLC with CI/CD integration** using **GitHub Actions**, managed through a **Kanban workflow**.

### Why Agile + CI/CD for Security?
- **Early security feedback:** Automated security checks run on every push and pull request.
- **Shift-left security:** Security analysis is introduced during sprint planning and enforced in the CI pipeline.
- **Continuous validation:** Linting, dependency checks, and security scans reduce risk before deployment.
- **Traceability:** GitHub commits and Actions logs provide evidence for security activities.

## 🔄 SDLC Method Comparison and Rationale

| Methodology | Why Not Selected | Security Impact |
|------------|-----------------|-----------------|
| **Kanban (Pure)** | Lacks time-boxed iterations and formal planning checkpoints. Security tasks can become deprioritized or delayed without explicit sprint goals. | Risk of inconsistent threat modeling and delayed security validation. |
| **Scrum** | Fixed sprint ceremonies (daily stand-ups, sprint reviews) can be heavy for a small academic team with limited scope and time. Security work may get compressed near sprint end. | Security testing may become reactive instead of continuous. |
| **Sprint-Only Model** | Focuses mainly on feature delivery within sprints without guaranteed automation between iterations. Does not inherently enforce security checks on every code change. | Misses opportunities for continuous security enforcement and early vulnerability detection. |
| **Agile + CI/CD (Chosen)** | — | Enables continuous security scanning, automated testing, and early detection of vulnerabilities at every commit and pull request. |


### Security Integration Points
| SDLC Stage | Security Activities |
|----------|--------------------|
| Sprint Planning | Identify threats, define security requirements |
| Development | Secure coding practices, input validation |
| CI Pipeline | Automated linting, dependency scanning, SAST |
| Review | Pull request reviews with security focus |

---

## 🧩 Technology Stack
**Frontend:** React (JavaScript library)  
**Backend:** Node.js (Express.js) *or* Python (Flask / FastAPI)  
**Database:** PostgreSQL  
**CI/CD:** GitHub Actions  

---

## 🛠️ Functional Requirements (Defined – Week 1)
### Authentication & User Management
- Secure login/logout
- Password hashing and least privilege user creation
- Logging of authentication attempts (Graduate requirement)

### Input Handling
- Secure input validation to prevent injection attacks
- Restricted file upload (single file, size/type validation)

### Database Security
- Parameterized queries
- Hashed passwords
- Restricted database access and audit logging

---

## 🧠 Threat Modeling Direction
- Attack surface identification (login, input fields, file upload, database)
- Login attack tree (credential attacks, injection, session abuse)
- Threats mapped to **CWE categories**
- Reference materials: **SANS**, **OWASP Top 10**

---

## 👥 Team Roles & Contributions
| Member | Role | Current Responsibilities |
|------|------|--------------------------|
| **Mohona** | Security Analyst | Threat modeling, CWE mapping, CI/CD security integration, SANS research |
| **Franklin** | Frontend Developer | React UI design, secure input handling |
| **Tet** | Backend Developer | API design, authentication logic, database schema |

Roles may rotate in later sprints.

---

## 📈 Current Status
- SDLC and CI/CD approach finalized
- Technology stack selected
- Team roles assigned
- Initial security requirements defined
- GitHub repository structure planned

---

## 🔜 Next Steps (Feb 17 Checkpoint)
- Initial attack surface documentation
- Login attack tree (depth ≥ 3)
- CWE mapping with mitigations
- CI/CD security tooling expansion

---
