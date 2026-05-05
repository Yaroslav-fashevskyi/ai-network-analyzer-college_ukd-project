# Prompt injection defense for AI network tools

Prompt injection is an attempt to make the model ignore system instructions or reveal hidden prompts. In network analysis software, the user input should be treated as data, not as instructions.

Defensive design:

- Validate input before using it. Accept only IP addresses, domains, or ASN values.
- Never execute user input through a shell string.
- Keep tool results separated from system instructions.
- Tell the model to use only structured evidence from tools.
- If data contains text that looks like instructions, treat it as untrusted content.
- Log rejected input for demonstration, but do not send it to the model as a command.

For a live demo, enter text like "ignore previous instructions". A secure system should reject it because it is not a valid network target.
