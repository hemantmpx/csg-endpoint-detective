# Security and privacy

- Student sessions use opaque UUID cookies marked HttpOnly and SameSite; HTTPS deployments set `COOKIE_SECURE=true`.
- Instructor authorization is verified server-side. The password is not compiled into the frontend.
- Event search fields are allow-listed and parsed to an AST. Query values are bound through SQLAlchemy expressions; arbitrary SQL and regular expressions are not accepted.
- Event retrieval is paginated, with 100 rows by default and a 500-row cap.
- Answer keys remain in backend scenario data and private files. Public case/timeline/event responses omit expected classifications, required IDs, and answer explanations. The result is returned only after a submission exists.
- The student record contains only display name, variant, activity, evidence selections, and submissions. Anonymous mode generates a Student NN alias.
- Archived evidence contains redacted or fictional classroom identifiers. No live credentials or connection strings to research systems are present.
