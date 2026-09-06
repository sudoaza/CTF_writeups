# rules

The event rules page contains the flag verbatim; the only task is to read it.
Category: misc (static, no files). Key idea: grep the rules text for the flag literal.

## Recon
- Challenge description: `Read the rules.`
- No files, no container.

## Analysis
Observation: the description is exactly "Read the rules." with no attachment.
Hypothesis: the flag is printed literally somewhere in the rules text.
Confirmation: fetching the rules page and searching for the flag prefix finds the
full flag string verbatim.

## Exploit
1. Fetch the rules page and grep for the flag pattern:
   ```
   curl -s <ctf-site>/rules | grep -o 'TFCCTF{[^}]*}'
   ```
   The flag string appears directly in the rules text.

## Full chain
1. `curl -s <ctf-site>/rules | grep -o 'TFCCTF{[^}]*}'`

## Flag
TFCCTF{M4ny_ch4ng3s...m0r3_3ff0rt}

## Lessons
- "Read the rules" challenges usually embed the flag verbatim; grep for the event
  flag format before overthinking.
