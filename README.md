# DF-017 login and file activity investigation

**All records, accounts, hosts, addresses and file paths are invented. The referenced files themselves are not supplied.**

## Case brief

A training evidence portal recorded repeated login failures and file-access
events on 20 October 2026. Determine which successful sessions meet the stated
rule and what subsequent downloads are recorded. Prioritise a session for
review without assuming an intrusion or attributing activity to a person.

The exports are deliberately unsorted and contain duplicate and malformed
records. Their timestamps use Z and +01:00 offsets. Assume both sources use
the same session-ID namespace. Clock accuracy, log completeness and the
real-world identity behind an account have not been independently established.

## Run from this folder

Python 3.10 or newer, standard library only. No notebook, pip install or API key.

| Purpose | macOS or Linux | Windows PowerShell |
| --- | --- | --- |
| Run starter or full analysis | `python3 analyze_case.py` | `py analyze_case.py` |
| Run login stage only | `python3 analyze_case.py --stage logins` | `py analyze_case.py --stage logins` |
| Check function 1 | `python3 check_solution.py LoginChecks` | `py check_solution.py LoginChecks` |
| Check function 2 | `python3 check_solution.py DownloadChecks` | `py check_solution.py DownloadChecks` |
| Run all checks | `python3 check_solution.py` | `py check_solution.py` |

If Windows does not recognise `py`, use `python` after checking that
`python --version` reports Python 3.10 or newer. Otherwise install Python 3.

Implement only `find_login_sequences` and `correlate_downloads` in
`analyze_case.py`. Their docstrings are the exact contracts. The supplied
loader, evidence, manifest and tests remain unchanged.

## Rules and field meanings

1. For every SUCCESS at T, group on `(username, source_ip, host)` and count
   FAIL events where **T - 5 minutes <= time < T**. Flag at least three.
   Each success is evaluated independently; earlier successes do not reset
   the window. A failure may support more than one alert.
2. Join file events using **username AND host AND session_id**. Keep only
   `action == "DOWNLOAD"`, `result == "SUCCESS"`, and **T <= time <= T + 10 minutes**.
   Count events, even if their paths repeat. Sum their integer bytes values.
   Retain alerts with zero matches. Sort by descending byte total, then time
   and success event ID. This ranking measures recorded volume, not guilt.
3. `event_id` identifies one event within its source. `session_id` links the
   two sources. `bytes` is the transfer size recorded by the application;
   independent transfer completion and destination evidence are not supplied.

## Evidence handling supplied for you

`evidence_tools.py` verifies the original CSV byte hashes against
`evidence_manifest.json`, trims outer whitespace, validates rows, requires
explicit timezone offsets, converts times to UTC and byte strings to integers,
and removes identical repeated event IDs. It records duplicate and rejected
CSV row numbers in `audit.json`. Conflicting versions of an ID stop analysis.
Rejected rows remain in the source; they are excluded from computed findings.

The starter writes `audit.json` before stopping at the first TODO. Function 1
adds `login_alerts.json`; the completed program adds `summary.json`. Rerun after
every change: old output files can be stale. A hash match demonstrates agreement
with this supplied baseline; it does not establish authenticity or completeness.
`.gitattributes` preserves CSV bytes through Git on all operating systems.

## Verified results -- complete this section
| Source | Data rows excluding header | Accepted unique | Duplicate | Rejected |
| --- | ---: | ---: | ---: | ---: |
| auth_log.csv | 60 | 54 | 1 | 5 |
| file_log.csv | 35 | 30 | 1 | 4 |

- SHA-256 check outcome and what it establishes: Both original CSV files passed SHA-256 verification against the supplied evidence manifest. This confirms consistency with the provided baseline, but does not independently prove authenticity, origin or completeness
- One rejected event ID and the exact rejection reason: Authentication event A900, located at CSV row 26 in `auth_log.csv`, was rejected because its timestamp was invalid. The audit recorded the exact reason: `Invalid isoformat string: 'not-a-time'`. This event was excluded from the analysis
- Number of flagged successful sessions: 3

| Success ID | Account | Session | Supporting failure IDs | Download IDs | Event count | Total bytes |
| --- | --- | --- | --- | --- | ---: | ---: |
| A005 | analyst01 | S-104 | A002, A003, A004 | F001, F002, F003 | 3    | 5,509,120 |
| A018 |	analyst02 |	S-304 | A015, A016, A017 |	F013             |	1  |	2,048 |
| A014 | backup_svc| S-204 | A011, A012, A013 |	None   	        | 0    |  0   |


## Manual evidence check -- do this without asking AI to count for you

For the highest-volume flagged session, find every supporting failure, the
success and every qualifying download in the original CSV files. Record their
original timestamps and UTC equivalents. Add rows as needed.

| Source and event ID | Original timestamp | UTC timestamp | What the row records |
| --- | --- | --- | --- |
| auth_log.csv A002 | 2026-10-20T08:58:00Z | 2026-10-20T08:58:00Z | Failed login; analyst01, 203.0.113.44, DF-PORTAL01; included at lower boundary |
| auth_log.csv A003 | 2026-10-20T09:00:00Z | 2026-10-20T09:00:00Z | Failed login; same account, IP and host |
| auth_log.csv A004 | 2026-10-20T10:01:00+01:00 | 2026-10-20T09:01:00Z | Failed login; same account, IP and host |
| auth_log.csv A005 | 2026-10-20T09:03:00Z | 2026-10-20T09:03:00Z | Successful login; analyst01, session S-104 |
| file_log.csv F001 | 2026-10-20T09:05:00Z | 2026-10-20T09:05:00Z | Successful DOWNLOAD, evidence_export.zip, 5,242,880 bytes |
| file_log.csv F002 | 2026-10-20T10:07:00+01:00 | 2026-10-20T09:07:00Z | Successful DOWNLOAD, interview_notes.pdf, 262,144 bytes |
| file_log.csv F003 | 2026-10-20T09:13:00Z | 2026-10-20T09:13:00Z | Successful DOWNLOAD, hashes.txt, 4,096 bytes; included at upper boundary |

- Manual sum of download bytes, showing the addition: F001 (5,242,880) + F002 (262,144) + F003 (4,096) = 5,509,120 bytes, matching summary.json.
- A001 versus A002: which qualifies for the A005 window and why? A005 succeeded at 09:03:00 UTC, so the five-minute failure window begins at 08:58:00 UTC. A001 occurred at 08:57:59 UTC, one second before the window, and is excluded. A002 occurred exactly at 08:58:00 UTC and is included because the lower boundary is inclusive.
- F003 versus F004: which qualifies for the A005 follow-up and why? A005 succeeded at 09:03:00 UTC, so its ten-minute download window ends at 09:13:00 UTC. F003 occurred exactly at 09:13:00 UTC and is included. F004 occurred at 09:13:01 UTC, one second after the boundary, so it is excluded.
- Why F005 is excluded even though the account matches: F005 has the same username (analyst01) and host (DF-PORTAL01) as A005, but its session ID is S-OTHER, not S-104. Therefore, it does not meet the three-field matching requirement.
- One +01:00 timestamp and its equivalent UTC time: A004 has the original timestamp 2026-10-20T10:01:00+01:00, equivalent to 2026-10-20T09:01:00Z. Subtracting one hour converts the timestamp to UTC.
- One limitation of excluding malformed records: Rejected events are not included in the calculations. If an excluded event represents a genuine login failure, successful login or download, the reported number of alerts or download totals may be incomplete.

## Checks actually run

Command, date and actual final result (paste output, including failures if any):

```text
Command: & "C:\Users\46764\anaconda3\python.exe" check_solution.py
Date: 3 November 2026

Ran 21 tests in 0.037s

OK
```

All 21 supplied checks should pass. Passing these checks is limited validation
of the stated classroom rule, not certification of a forensic tool.

## AI interpretation and our final finding

Prompt 3 response about the overstated claim (keep the actual response):

> The logs do not identify an attacker or establish who operated the account. Recorded DOWNLOAD events do not prove theft, authorization status, or completed exfiltration. Matching SHA-256 hashes establish consistency with the supplied manifest, not authenticity or completeness. Events A002–A005 and F001–F003 support prioritizing session S-104 for review but do not establish criminal activity.

**Rewritten claim:** Session S-104 recorded three qualifying downloads totaling 5,509,120 bytes after successful login A005 and merits investigation. The supplied CSV hashes match the manifest, but identity, unauthorized activity, authenticity and completeness remain unverified.

One claim we corrected or independently verified, with event IDs:

We verified that A002 occurred exactly five minutes before successful login A005 and was included, while A001 occurred one second too early and was excluded. We also verified that F003 occurred at the ten-minute download boundary and qualified, while F004 occurred one second afterward and was excluded. The qualifying download events F001, F002 and F003 total 5,509,120 bytes, matching summary.json.

Final 180-220 word finding, reviewed and edited by the pair:
The DF-017 investigation identified three successful login sessions preceded by at least three failed login attempts within five minutes.

Session S-104, associated with account analyst01, had the highest recorded download volume. Authentication events A002, A003 and A004 preceded successful login A005 at 09:03:00 UTC on 20 October 2026. File events F001, F002 and F003 recorded three successful downloads between 09:05:00 and 09:13:00 UTC, totaling 5,509,120 bytes.

By comparison, session S-304, associated with successful login A018, recorded one qualifying download, F013, totaling 2,048 bytes. The greater recorded volume makes S-104 the priority for further investigation.

However, two limitations affect interpretation. First, the logs do not establish who controlled the account or whether the activity was authorized. Second, malformed records were excluded, and the completeness of the original evidence has not been independently established.

A plausible benign explanation is that an authorized employee entered an incorrect password repeatedly before downloading files for legitimate work.

Further investigation should request identity-provider authentication records, including MFA verification details, and independent network transfer or destination logs to establish whether transfers completed and where data was sent.

The evidence identifies suspicious patterns requiring review, not proven intrusion or theft.

It must cite evidence IDs, separate observation from inference, include a
comparison session, two limitations, one benign explanation and two next
evidence requests. Do not claim that an account or IP identifies a person.

## AI use and pair review

- Names of both partners: Jerin Jacob
- GenAI tool/ChatGPT date and displayed model: ChatGPT, GPT-6, 3 November 2026.
- Prompts used and what they produced: Prompt 1 assisted with login-sequence detection. Prompt 2 assisted with download correlation. The debugging follow-up helped correct the sorting rule. Prompt 3 reviewed unsupported forensic claims. Prompt 4 produced a draft finding for human review.
- One follow-up question or correction, with a short response excerpt: The original download correlation function sorted by success time rather than descending total bytes. ChatGPT suggested changing the sorting key to (-total_bytes, success_time, success_id). After this correction, all 21 tests passed.
- Results of code and evidence checks performed: All 21 tests passed on 3 November 2026. Authentication events A001–A005 and file events F001–F005 were compared against the original CSVs. The three qualifying download values were checked against the reported total of 5,509,120 bytes.


## Submit

Submit one public repository URL per pair through the course route. Include the ten
starter project files and the newly generated `audit.json`, `login_alerts.json`,
and `summary.json`. Complete this README. The repository needs a starting
commit and a finished commit. The accompanying student guide gives the
90-minute schedule; `GitHub_CLI_Guide.docx` covers setup and upload.
Only synthetic exercise files belong in this repository. Keep credentials out.

Optional stretch after the core task: use the interactive Python console to
compare `min_failures=2` with `min_failures=3`, without changing the defaults or
original evidence. Which extra session appears, and does that change what you
can conclude? Record this separately from the required default output.
