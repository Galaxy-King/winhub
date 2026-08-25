# Безпека Agent Gateway

## Controls

- rate-limited enrollment;
- optional source allowlist;
- manual Pending Approval;
- per-host auth token;
- RSA identity key;
- signed requests із body hash, nonce і timestamp;
- signature freshness;
- Task v2 per-agent RSA-PSS;
- sequence/replay protection;
- blocked re-enrollment за замовчуванням;
- package SHA-256 validation.

## Rollout policy

Під час rollout enrollment відкривається лише на необхідний час/джерела. Після стабілізації його закривають або обмежують. Legacy signature bridge не вмикайте на fresh install.

Компрометований endpoint спочатку блокується server-side, потім ізолюється мережею та перевстановлюється з новою identity.
