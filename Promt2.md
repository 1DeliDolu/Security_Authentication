# Activity: Debugging and Resolving Security Issues Using Microsoft Copilot

### **Using Microsoft Copilot to Debug and Resolve Security Vulnerabilities**

# Introduction

Even with secure coding practices, vulnerabilities can still exist. In this activity, you’ll use Microsoft Copilot to debug and resolve security vulnerabilities in the SafeVault application. This includes identifying issues like SQL injection risks and XSS vulnerabilities, applying fixes, and testing the corrected code to ensure it’s secure.

This is the final activity in the project, ensuring the SafeVault application is secure and ready for deployment.

# Instructions

## Step 1: Review the scenario

You’ve implemented secure coding practices and access control mechanisms in SafeVault, but further testing has revealed potential vulnerabilities. These include:

* SQL injection risks in database queries.
* Cross-site scripting (XSS) risks in handling user-generated content.

Your goal is to debug these issues using Microsoft Copilot and apply fixes to secure the application.

## Step 2: Identify vulnerabilities in the codebase

Use Copilot to:

* Analyze the codebase and identify insecure queries or output handling.
* Detect specific vulnerabilities such as:
  * Unsafe string concatenation in SQL queries.
  * Lack of input sanitization in form handling.

## Step 3: Fix security issues with Copilot

Use Copilot’s suggestions to:

* Replace insecure queries with parameterized statements.
* Sanitize and escape user inputs to prevent XSS attacks.

## Step 4: Test the fixed code

Use Copilot to:

* Generate tests that simulate attack scenarios, such as:
  * SQL injection attempts with malicious input.
  * XSS attacks through form fields.
* Verify that the fixed code effectively blocks these attacks.

## Step 5: Save and summarize your work

By the end of this activity, you will have:

* Debugged and secured the SafeVault codebase against common vulnerabilities.
* Tests confirming the application’s robustness against attacks.

Save the debugged and secured codebase in your sandbox environment. Prepare a summary of the vulnerabilities identified, the fixes applied, and how Copilot assisted in the debugging process.
