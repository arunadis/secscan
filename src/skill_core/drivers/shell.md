Run the pipeline with the scan command (resumes automatically as needed). From
this skill directory, put `scripts/` on `PYTHONPATH`:

```bash
export PYTHONPATH="$(dirname "$0")/scripts"          # or the skill's scripts/ path
python -m pipeline.scan_cli init   --workdir <scan-root>
python -m pipeline.scan_cli run    --workdir <scan-root> [--profile quick|full|audit] [--full] [-q|-v]
python -m pipeline.scan_cli status --workdir <scan-root>
python -m pipeline.scan_cli report --workdir <scan-root> [--repo <name>]
```

If the package is installed globally the same surface is `secscan run ...`.

Exit code 3 from `run` means your reasoning is required — see the next section.

`run` reports progress on **stderr** as it works (each stage, segment `i/N`,
external tool, and coverage note, plus a heartbeat during long steps); relay it to
the user so a long scan does not look stuck. The summary stays on **stdout**. The
full trace of the latest run is always in `.secscan/scan.log` — read it first when a
scan stopped unexpectedly (its last line names the stage that was in progress).
Pass `-q` if you only want the summary.

When the project is configured with an external analysis endpoint (`llm.endpoint`),
you do not perform the reasoning; the provider does, through its **batch API by
default**. Expect `batch k/m submitted` / `processing c/N` / `ended` lines and a wait
in the foreground that can last minutes to hours. Do not kill and restart the scan to
"speed it up": the batch reference is persisted and a re-run resumes the same batch.
Exit code 1 with `re-run to resume` on stderr means the endpoint kept refusing after
all retries (typically rate limiting); segments already analysed are kept, so re-run
later rather than starting over. `--policy interactive` opts into live per-segment
requests for small repositories.
