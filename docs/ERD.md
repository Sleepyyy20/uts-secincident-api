# ERD - SecIncident API

![ERD](erd.png)

Diagram Mermaid (dirender otomatis oleh GitHub):

```mermaid
erDiagram
    USERS ||--o{ ASSETS : "memiliki (owner_id)"
    USERS ||--o{ INCIDENTS : "melaporkan (reporter_id)"
    USERS |o--o{ INCIDENTS : "menangani (assignee_id)"
    USERS |o--o{ AUDIT_LOGS : "melakukan (user_id)"
    ASSETS ||--o{ VULNERABILITIES : "memiliki"
    INCIDENTS ||--o{ INCIDENT_ASSETS : "berdampak pada"
    ASSETS ||--o{ INCIDENT_ASSETS : "terdampak oleh"

    USERS {
        int id PK
        string username UK
        string email UK
        string password_hash
        string role
        bool is_active
        datetime created_at
    }
    ASSETS {
        int id PK
        string name UK
        string asset_type
        string ip_address
        string criticality
        string status
        int owner_id FK
        datetime created_at
    }
    INCIDENTS {
        int id PK
        string title
        text description
        string incident_type
        string severity
        string status
        int reporter_id FK
        int assignee_id FK
        datetime detected_at
        datetime resolved_at
        datetime created_at
        datetime updated_at
    }
    INCIDENT_ASSETS {
        int incident_id PK, FK
        int asset_id PK, FK
        string impact_note
        datetime linked_at
    }
    VULNERABILITIES {
        int id PK
        int asset_id FK
        string title
        string cve_id
        float cvss_score
        string severity
        string status
        datetime discovered_at
        datetime created_at
    }
    AUDIT_LOGS {
        int id PK
        int user_id FK
        string action
        string entity_type
        int entity_id
        text detail
        string ip_address
        datetime created_at
    }
```

Catatan: `UNIQUE(asset_id, cve_id)` pada `vulnerabilities`; semua kolom enum dijaga `CHECK constraint`;
foreign key memakai `ON DELETE RESTRICT` (kecuali `incident_assets.incident_id` = `CASCADE`).
