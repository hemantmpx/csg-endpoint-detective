# Instructor guide

## Start a class

1. Copy `.env.example` to `.env` and set unique values for `POSTGRES_PASSWORD`, `CLASS_CODE`, and `INSTRUCTOR_PASSWORD`.
2. From this repository, run `docker compose up --build -d`. The API waits for healthy PostgreSQL and freezes all seeded scenario event corpora before becoming ready.
3. Open `http://localhost:8080/instructor`, sign in with `INSTRUCTOR_PASSWORD`, and review the active lab and enabled cases.
4. Share `http://<classroom-host>:8080` and `CLASS_CODE` with students. They need only a display name or anonymous mode.

`ADDITIONAL_CLASS_CODES` accepts comma-separated alternate join codes for this same class. They share the same roster, case settings, and progress records; the existing `CLASS_CODE` remains active. This deployment also accepts `drshujaisthebest`.

The instructor dashboard shows online presence (seen in the last five minutes), case progress, classification distributions, and optional anonymized search strategy. Use search history to guide discussion, not for punitive grading. The CSV export includes each investigation item and the student's written explanation so you can review reasoning and the final incident reconstruction.

For a live teaching script, see the [professor-led lab walkthrough](professor-lab-walkthrough.docx). For the full-score steps, case-by-case answer key, and model explanations, see the instructor-only [teacher’s manual](teacher-manual.md).

## Run and stop the lab

Use Guided mode to unlock the next case after the current case is submitted, or Challenge mode to make enabled cases available. Toggle cases in the dashboard, pause/resume the class, and reset a learner's progress when needed. `make down` stops containers while retaining the database volume. `make reset-lab` deletes the database volume and recreates a clean seeded classroom.

## Capacity

Scenario events are generated from fixed seeds at server startup and stored in PostgreSQL with scenario/variant/time and searchable-field indexes. Each student receives an independent cookie session and variant. The UI never downloads a case's full event set; event results are paginated.
