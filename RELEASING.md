# Release Process

This repository uses automatic versioning and releases based on git tags.

## How to Create a Release

1. **Update the CHANGELOG.md** (optional but recommended)
   - Add a new section for the version you're releasing
   - Document what changed in this release

2. **Create and push a version tag**
   ```bash
   git tag v0.2.2
   git push origin v0.2.2
   ```

3. **Automatic process triggered**
   - GitHub Actions workflow will automatically:
     - Build the package with version extracted from the tag (e.g., `0.2.2`)
     - Publish to PyPI
     - Create a GitHub release with auto-generated release notes

## Version Scheme

- Tags should follow the pattern `vX.Y.Z` (e.g., `v0.2.2`, `v1.0.0`)
- The `v` prefix is stripped automatically to create the package version
- Uses [Semantic Versioning](https://semver.org/)

## Technical Details

- Version is managed by `setuptools-scm` which extracts it from git tags
- Version is defined as `dynamic` in `pyproject.toml`
- No need to manually update version numbers in code files
- The CD workflow (`.github/workflows/cd.yml`) handles publication and release creation
