
# Iteration Wallet – Project Pitch & Concept

## Core Idea
Iteration Wallet is a project safety and version preservation system designed to prevent catastrophic loss of work.
Unlike traditional version control systems such as Git, Iteration Wallet prioritizes non‑destructive workflows.

The system preserves protected canonical copies of important project states inside a secure structure called the Vault.

## Goals
- Prevent accidental deletion or overwriting of critical work
- Require intentional user actions for destructive operations
- Preserve canonical project versions
- Allow automatic detection of improved code modules

## Key Components

### Vault
Protected storage for canonical versions.

Vault files cannot be:
- opened
- edited
- overwritten
- batch deleted

Vault files can only be:
- copied
- individually removed

### Cradle
Each project version receives a cradle inside the Vault.

Example
Project → Workspace/V5 → Vault/Cradle/V5

The cradle stores the canonical snapshot.

### Archive
Older versions move to the Archive when replaced.

Vault/Archive/V5

### Philosophy
Iteration Wallet assumes humans make mistakes.
Therefore important files require intentional steps to remove or destroy.
