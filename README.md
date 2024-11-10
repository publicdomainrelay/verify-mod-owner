# Verify Modifications to Policy via Owner Signatures on Git Commits

This GitHub Action verifies the signatures of commits to ensure they are signed by trusted PGP or SSH keys. It loads the provided public keys into an object, where keys are the email addresses (for PGP keys) or SSH key comments, and both PGP and SSH keys can be arrays within this object.

## Inputs

### `base_branch`

**Optional** The base branch to compare against. Default is `main`.

### `file_path`

**Optional** The file path to check for modifications.

### `public_key_files`

**Required** Multi-line input of paths to public key files. Each line should be a path to a public key file checked into your repository.

### `commits`

**Optional** JSON-encoded array of commit SHAs. If not provided, the action will compute the commits that differ from the `base_branch` and that modify the `file_path` (if provided).

## Example Usage

```yaml
name: Verify Commits

on: [push]

jobs:
  verify_commits:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Verify Commit Signatures
        uses: ./
        with:
          base_branch: 'main'
          file_path: 'src/'
          public_key_files: |
            keys/alice_pgp_public.asc
            keys/bob_ssh_public.pub
```

In this example, the action will:

- Compare the commits in the current branch against `main`.
- Only consider commits that modify files under the `src/` directory.
- Load the public keys from `keys/alice_pgp_public.asc` and `keys/bob_ssh_public.pub`.
- Verify the signatures of the commits.

## Passing in All Commits Which Differ from a Specified Base Branch for Commits Which Modify a Given File Path

If you want to verify all commits that differ from a specified base branch and modify a given file path, you can omit the `commits` input, and the action will compute them automatically.

```yaml
with:
  base_branch: 'develop'
  file_path: 'src/components/'
  public_key_files: |
    keys/alice_pgp_public.asc
    keys/bob_ssh_public.pub
```

In this example, the action will:

- Compare the commits in the current branch against `develop`.
- Only consider commits that modify files under `src/components/`.
- Load the public keys specified.

## Notes

- **Public Key Files**: The public key files should be present in your repository so that the action can read them. Include them in your repository under a directory like `keys/`.
- **SSH and PGP Keys**: Both SSH and PGP keys are supported. The action can handle multiple SSH or PGP keys per email address or SSH comment.
- **SSH Signature Verification**: SSH signature verification is fully implemented using `ssh-keygen`. Ensure that `ssh-keygen` is available in the runner environment (it is available in `ubuntu-latest` runners).
- **Error Handling**: The action will fail if any commit is not properly signed or if the signature verification fails.

## Dependencies

- **openpgp**: For verifying PGP signatures.
- **sshpk**: For handling SSH keys.
- **ssh-keygen**: The action uses `ssh-keygen -Y verify` to verify SSH signatures.

## License

[Unlicense](LICENSE)
