# Software Security (CS 4417 / CS 6417)
## Secure Software Design and Implementation – Winter 2026

### Week 1 Progress Report

---

## **Project Overview**
This project focuses on designing and implementing a small secure web-based application while applying software security principles across the Software Development Life Cycle (SDLC). Emphasis is placed on secure design, threat modeling, attack surface analysis, and validation rather than exploitation.

---

## **Technology Stack Selection**

### **Frontend**
- **React (JavaScript)**
- Reasoning:
  - Component-based architecture improves separation of concerns.
  - Strong ecosystem for input validation and secure UI handling.
  - Widely used and well-supported with security-focused linting tools.

### **Backend**
- **Node.js with Express.js** *(Primary choice)*
  - Lightweight and suitable for RESTful APIs.
  - Large ecosystem of security middleware (e.g., Helmet, express-validator).
  - Easy integration with CI/CD pipelines.
- *(Python FastAPI kept as a backup alternative if needed)*

### **Database**
- **PostgreSQL**
- Reasoning:
  - Strong support for parameterized queries.
  - Role-based access control.
  - Supports encryption at rest and audit logging extensions.

---

## **SDLC Choice**

### **DevOps with Security Integration (DevSecOps)**
We selected a DevOps-based SDLC to ensure that security is integrated early and continuously.

**Security integration points:**
- **Planning Phase:** Identification of authentication, authorization, and input validation requirements.
- **Development Phase:** Secure coding practices (password hashing, parameterized queries).
- **CI/CD Pipeline:** Automated linting, dependency scanning, and security testing using GitHub Actions.
- **Testing Phase:** Validation of login, input handling, and database access controls.

---

## **CI/CD Tooling**

### **GitHub Actions**
GitHub Actions is used to automate:
- Dependency installation
- Static analysis and linting
- Security scanning
- Automated testing

This ensures early detection of vulnerabilities and enforces secure coding practices.

---

## **Initial Attack Surface Identification**

Identified entry points include:
- Login and authentication endpoints
- Password change functionality
- User creation (least privilege)
- Input fields (feedback/contact form)
- File upload endpoint (restricted – graduate requirement)
- Database access layer

---

## **Team Roles & Contributions (Week 1)**

- **Developer**
  - Defined application architecture
  - Selected frontend, backend, and database stack
- **Security Analyst**
  - Identified initial attack surface
  - Began mapping potential threats to CWE categories
- **Tester**
  - Planned authentication and input validation test cases
  - Reviewed CI/CD testing requirements

---

## **Next Steps (Week 2)**
- Build authentication flow (login/logout/password change)
- Implement database schema with hashed passwords
- Expand attack tree and CWE mapping
- Integrate security scans into CI pipeline
