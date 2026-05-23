# Session recording (assignment deliverable)

## Included recordings

| Artifact | Description | How to view |
|----------|-------------|-------------|
| `docs/output/demo_recording.log` | Full demo output (build, tests, E2E, PCAP) | Any text editor |
| `docs/output/demo_session.script` | Terminal session capture (`script` format) | `less docs/output/demo_session.script` |
| `docs/output/pcap/ike_e2e_*.pcap` | IKE packet capture | `tcpdump -r ... -n -vv` |
| Cursor chat export | Full AI working session | Export from Cursor (see below) |

## Regenerate demo recording

```bash
chmod +x scripts/record_demo.sh
./scripts/record_demo.sh
# or with script(1):
script -q -f -c "bash ./scripts/record_demo.sh" docs/output/demo_session.script
```

## Optional: asciinema (terminal video)

If `asciinema` is installed:

```bash
pip install asciinema   # or: sudo dnf install asciinema
asciinema rec -c "./scripts/record_demo.sh" -t "IKEv2 LB Demo" docs/output/demo.cast
asciinema play docs/output/demo.cast
# Upload: asciinema upload docs/output/demo.cast
```

## Optional: screen video (MP4)

Record your screen while running:

```bash
./scripts/record_demo.sh
```

Tools: OBS Studio, SimpleScreenRecorder, or `ffmpeg` (with display):

```bash
ffmpeg -f x11grab -video_size 1920x1080 -framerate 15 -i :0.0 -t 300 docs/output/demo.mp4
```

## What the demo shows

1. `make show-config` — LB limits (65536 sessions, 32 backends)
2. `make test` — 30/30 unit tests PASS
3. `run_e2e_tcpdump.sh` — IKE_SA_INIT via `ike-lb` + PCAP
4. `run_multi_session_e2e.sh` — 5 sessions across backends
5. Listing of PDF, PCAP, and documentation

## Cursor session export (required by brief)

1. Open this project in Cursor  
2. Chat panel → **⋯** → **Export chat** (or copy full transcript)  
3. Save as `docs/output/cursor_session_export.md` or `.pdf`

## Submission bundle

Attach together:

- `docs/output/IKEv2_LoadBalancer_Report.pdf`
- `docs/PROMPTS.md`
- `docs/output/demo_recording.log` (or `.script` / `.cast` / `.mp4`)
- Cursor session export
- Optional: `docs/output/pcap/ike_e2e_*.pcap`
