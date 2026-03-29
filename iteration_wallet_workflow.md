
# Iteration Wallet – System Workflow

## 1. Project Creation
Program creates:

Projects/
    Project_Name/
        Workspace/
        Vault/
            Cradle/
            Archive/
        Removed_Files/
        Metadata/

## 2. Version Folder Creation
User creates a version folder inside Workspace.

Example:
Workspace/V5

Program automatically creates a cradle:

Vault/Cradle/V5

## 3. Storing Canonical Version
User selects "Save Version to Vault".

Program copies:
Workspace/V5

to

Vault/Cradle/V5/Canonical

## 4. Opening the Vault

User must type:

OPEN

Vault unlocks temporarily.

## 5. Removing Files From Vault

Steps:
1 Open Vault (type OPEN)
2 Select version
3 Click REMOVE

Program moves version to:

Removed_Files/

## 6. Deleting Removed Files

User selects delete.

Program requires confirmation:

DELETE

Only then will the file be erased.

## 7. Version Analysis

Every file entering a version folder is scanned.

Categories detected:
- frontend
- backend
- security
- engine
- orchestrator
- media

Improved modules may generate candidate versions such as:

V5.1
V5.2
V5.3

## 8. Promotion

If a candidate becomes stable:

Old canonical version → Archive
New candidate → Cradle

## 9. USB Protection

When a vault exists on an external drive:

Marker file:
.iteration_wallet_vault

Drive formatting is blocked until:
- vault opened
- vault emptied
- vault removed
