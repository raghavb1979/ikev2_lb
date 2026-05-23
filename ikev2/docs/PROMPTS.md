# Prompt log — user prompts only

Per assignment: *“Must Provide all the prompts used.”*  
Listed below are **user prompts only** (no assistant text, no system notifications, no duplicates).

| # | Type | Prompt |
|---|------|--------|
| 1 | Assignment brief | See [Prompt 1](#prompt-1-assignment-brief) |
| 2 | Implementation | `can you create the code now?` |
| 3 | Implementation | `can you create the c files with make file?` |
| 4 | Clarification | `you understood the problem statement clearly?` |
| 5 | Problem statement | See [Prompt 5](#prompt-5-problem-statement) |
| 6 | Testing | `test plan and test it?` |
| 7 | Design | `how many requests handled concurrently` |
| 8 | Build | `configurable at build time and now configure to the current value you have` |
| 9 | Cleanup | `is the python file inside src/ikev2` |
| 10 | Cleanup | `if not required remote` |
| 11 | Submission | `can you please generate a ppt or pdf of the steps done and the prompt string` |
| 12 | Testing | `generate any kind of tcpdump and end to end testing for this ?` |
| 13 | Interop | `all the interop with algorithms flow tested` |
| 14 | Interop | `the interop is required for only the structure or algorithms in the IKE any other scenarios need to be addressed?` |
| 15 | Documentation | `please update the required vs optional scenarios` |
| 16 | Documentation | `updated the prompt string document only required prompt strings used?` |

**Excluded (not user task prompts):**

- System: *“Briefly inform the user about the task result…”* (Cursor task notifications)
- Duplicate: second *“test plan and test it?”* (same as #6)
- Meta: *“plit into Required / Recommended / Optional checkboxes. Regenerate submission PDF…”* (folded into #15 doc update work)

---

## Prompt 1 (assignment brief)

```
Common Instructions:

Use any AI tools for the task given
Submission format post completion: PDF/Doc/Videorecording
Must Provide all the prompts used
Record the whole session – Copy of whole working session

What Good Looks Like (Guidance):

Structured Thinking: Clear breakdown (HLD → LLD → Execution → Testing/Validation)
Explaining design decisions
Correctness and Scalability of the solution
Clarity: Simple diagrams, clean explanation of flow
Practicality: Real-world considerations
AI Usage: Demonstrating how AI helped

Evaluation Criteria:

Problem-solving approach
System design clarity
Effective use of AI tools in SDLC
Use of advanced AI approaches
Depth of technical understanding
Communication and structure
```

## Prompt 5 (problem statement)

```
Problem

I have below IKEv2 implementation.

https://github.com/openiked/openiked-portable

I want to implement IKEv2 load balancer in my large network of routers (Hub-Spoke topology). My router should interop with StrongSwan devices (Working in Client or Server role)

https://github.com/strongswan/strongswan
```
