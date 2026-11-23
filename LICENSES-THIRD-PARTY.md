# Third-party licenses

| Component | License | Use |
| --- | --- | --- |
| safe-coordination-of-untrusted-ai-agents (vgc kernel) | MIT | vendored in src/inert/runtime/kernel.py |
| microsoft/TAMAS code | MIT | evaluators vendored, read-only |
| microsoft/TAMAS data | CDLA-Permissive-2.0 | scenarios vendored, read-only |
| Open-weight models (Qwen2.5, Llama 3.x, Gemma 2, Mistral) | per model license | served offline via Ollama |
| pydantic, PyYAML, hypothesis, pytest | MIT / BSD / MPL-2.0 | dependencies |

Payload libraries carry a dual-use notice (src/inert/attacks/__init__.py). No payload targets a
real third-party service: all targets use the reserved example domain `evil.example`.
