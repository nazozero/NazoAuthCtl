# NazoAuthCtl v0.2.28

- Simplify `status` and `status --all` to one row per instance: name, host,
  release version, health and latest backup time in UTC. Hide internal IDs and
  artifact digests from the default view; retain existing JSON fields and add
  `version` (null when no release version is recorded).
- Select Chinese or English for core help, status and error headings/labels
  using the first nonempty `LC_ALL`, `LC_MESSAGES` or `LANG`, shared with the
  OIDF entry point. Diagnostic details and stable error codes retain their text.
- Include the specific failure reason in text errors and align Chinese table
  columns by display width.

Artifact verification and deployment mutation behavior are unchanged by these
presentation changes. See [the operations guide](../README.md#operations).
