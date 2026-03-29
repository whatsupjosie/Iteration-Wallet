
# Iteration Wallet – AI Build Instructions

This document describes how to build the Iteration Wallet software.

## Core Modules

Vault Manager
Project Manager
Version Analyzer
Candidate Builder
Archive Manager
USB Protection Manager
Command Confirmation System

## Vault Manager Responsibilities

- create vault directories
- enforce read protection
- block direct editing
- allow copy operations
- enforce REMOVE workflow

Vault files must never be deleted directly.

## Confirmation Commands

Vault access requires:

OPEN

Permanent deletion requires:

DELETE

Both commands should be case‑sensitive.

## Removal Workflow

Correct order:

1 Select vault file
2 Press REMOVE
3 File moves to Removed_Files
4 User selects delete
5 User types DELETE

Only then can deletion occur.

## Version Analyzer

Scan version folders for components:

frontend
backend
security
engine
orchestrator
media

Compare with canonical version stored in the vault.

## Candidate Builder

If improvements detected:

Create editable candidate builds.

Example:
V5.1
V5.2
V5.3

Candidates can later replace canonical versions.

## Archive Manager

When promoting a candidate:

Old version → Vault/Archive

Archive files remain protected.

## USB Protection Manager

When a vault is placed on external storage:

Create marker file:

.iteration_wallet_vault

Formatting should be blocked until the vault is emptied and removed.

## Safety Rules

Never allow:
- automatic deletion
- batch deletion in vault
- automatic overwriting of canonical versions
