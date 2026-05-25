# Documentation index

| Document | Purpose | Updated |
|----------|---------|---------|
| [DESIGN.md](DESIGN.md) | HLD / LLD, flow summary, scalability | Yes |
| [FLOWS.md](FLOWS.md) | **Simple diagrams** (Mermaid) + step-by-step flows | Yes |
| [INTEROP.md](INTEROP.md) | StrongSwan ↔ OpenIKED; **Required / Recommended / Optional** scenarios; config samples; go-live checklist | Yes |
| [INTEROP_ALGORITHM_STATUS.md](INTEROP_ALGORITHM_STATUS.md) | What is automated vs manual for algorithm interop | Yes |
| [TEST_PLAN.md](TEST_PLAN.md) | Unit, integration, E2E, tcpdump, manual S-01–S-04; **§2 practicality** | Yes |
| [PRACTICALITY.md](PRACTICALITY.md) | **Real-world** ops, lab vs prod flows, test→production mapping | Yes |
| [PROMPTS.md](PROMPTS.md) | **User prompts only** (16 entries, no duplicates) | Yes |
| [SUBMISSION_REPORT.md](SUBMISSION_REPORT.md) | Steps, summary, link to PROMPTS.md | Yes |
| [output/IKEv2_LoadBalancer_Report.pdf](output/IKEv2_LoadBalancer_Report.pdf) | Generated PDF (`make submission-docs`) | Regenerate after doc edits |
| [output/IKEv2_LoadBalancer_Report.pptx](output/IKEv2_LoadBalancer_Report.pptx) | Generated PPTX | Regenerate after doc edits |
| [output/pcap/README.md](output/pcap/README.md) | E2E packet capture notes | Yes |
| [RECORDING.md](RECORDING.md) | Demo recording / session export guide | Yes |
| [output/demo_recording.log](output/demo_recording.log) | Captured demo run | Run `make record` |
| [output/demo_recording.html](output/demo_recording.html) | Browsable recording | Run `make record` |

## Regenerate submission PDF/PPTX

```bash
make submission-docs
```

Refresh interop log, debug bundle, and PDF/PPTX in one step (requires root):

```bash
sudo ./scripts/refresh_submission_artifacts.sh
```

## Run all tests

```bash
make test-all
make test-e2e-multi
sudo make test-interop-real    # S-01 StrongSwan (see INTEROP_ALGORITHM_STATUS.md)
make test-e2e-pcap             # verify PCAP on your host
```
