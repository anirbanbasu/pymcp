# Contributing

Thank you for your interest in contributing to PyMCP. Pull requests are welcome. However, please open an issue first to discuss what you would like to change.

## Prerequisites

Follow the [installation instructions in the README](README.md#installation).

Install [`prek`](https://prek.j178.dev/installation/) and install all dependencies using `just install-all` for the installation of PyMCP.

Then enable `pre-commit` hooks by running the following in the _WD_.

```bash
just install-pre-commit-hooks
```

Also, check all the available development-specific targets by running `just -l`, e.g., `type-check`, `format`, etc.

## Licensing & Contributions

By contributing to this project, you agree to the following:

1. **License:** Your contributions will be licensed under the **MIT License**.
2. **Developer Certificate of Origin (DCO):** To ensure a clear chain of ownership, we strongly encourage all commits to be "signed-off." However, this has not yet been enforced through a workflow yet.

### Developer Certificate of Origin (DCO)
By adding `Signed-off-by: Your Name <email@example.com>` to your commit message, you certify that you have the right to submit the work under the terms of the [Developer Certificate of Origin 1.1](https://developercertificate.org).

To protect your privacy, you may use your _GitHub-provided no-reply email address_ or any other aliases for your signatures.

If you use the GitHub-provided no-reply email, every signed-off commit, will look similar to `Signed-off-by: Real Name <username@users.noreply.github.com>`.
