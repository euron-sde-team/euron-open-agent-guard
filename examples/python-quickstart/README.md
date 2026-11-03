# Python quickstart

One agent, four actions, four different answers.

```bash
pip install ./sdks/python                   # from the repository root (PyPI is on the roadmap)
eval "$(uv run --with httpx python examples/bootstrap.py)"   # or use the dashboard
python examples/python-quickstart/quickstart.py
```

Output (ids differ):

```text
refund 40      -> allow            Granted by role example-support
refund 900     -> require_approval Refunds over 500 need a person
                  approve it at http://localhost:5110/approvals/...
shell          -> deny             Agents do not get a shell
export         -> restrict         obligations {'max_rows': 10, 'redact_fields': ['email']}

refund(25) -> refunded 25 to c-1002
refund(900) -> waits for approval ...
refund(20000) -> denied (policy_deny)
```

Approve the 900 refund in the dashboard and run the same `authorize` call again: it is
allowed once, because the approval is bound to those exact parameters.
