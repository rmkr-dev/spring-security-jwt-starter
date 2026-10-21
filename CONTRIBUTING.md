# Contributing

Thanks for taking the time to help. Bug reports, fixes, docs improvements and feature ideas are all
welcome.

## Before you start

- For anything bigger than a small fix, please open an issue first so we can agree on the approach
  before you spend time on it.
- Security problems go through the private process in [SECURITY.md](SECURITY.md), not public issues.

## Building

You need Java 17 or newer and Maven 3.8.6 or newer.

```bash
mvn -B verify
```

This compiles every module, runs the unit and integration tests and checks coverage. Compiler warnings
fail the build. The Maven enforcer also requires dependency convergence and upper-bound versions.
Tests use locally generated keys and WireMock, so no Entra tenant or network access is needed.

Pull requests run `.github/workflows/pr-validation.yml` on Java 17, 21 and 25, plus a release
packaging check, dependency review, and repository hygiene. Dependency review fails the pull request
when a newly added or upgraded package has a moderate or higher known vulnerability. The **PR
validation** job fails if any of those fail. See [docs/compatibility.md](docs/compatibility.md).

### Coverage

JaCoCo runs as part of `verify`. Each library module (`entra-security-core`,
`entra-security-spring-boot-starter`, `entra-security-test`) has a line and branch minimum set just
below its current coverage, so a change that drops coverage fails the build. HTML reports land in
`<module>/target/site/jacoco/index.html`, and CI attaches them to every run as the `coverage-reports`
artifact.

If your change adds code, add tests with it. Please do not lower a minimum to get a build to pass.

## Making a change

1. Fork the repository and create a branch from `main`.
2. Keep the change focused: one fix or feature per pull request.
3. Add or update tests. Bug fixes should come with a test that fails without the fix.
4. Update `README.md` for user-facing behaviour or configuration changes, and add an entry under
   `## [Unreleased]` in `CHANGELOG.md`.
5. Run `mvn -B verify` locally.
6. Open a pull request and fill in the template.

### Code style

- Follow the style of the surrounding code: four-space indentation, no wildcard imports.
- The build compiles with `-Xlint:all`; please do not add new warnings.
- Public API in `entra-security-core` and the starter should have Javadoc.
- Never log full tokens, secrets or key material. Use `SafeClaimLogger` for claim logging.

### Commits

Write commit messages in the imperative mood ("Add X", "Fix Y"), with a short subject line and, when
it helps, a body explaining why. Small, self-contained commits are easier to review than one large
one.

## Dependencies

Dependabot opens weekly pull requests for Maven dependencies and GitHub Actions. Spring Boot major
upgrades (Boot 5 and later) are excluded on purpose; they are planned as separate work.

CI builds the pinned Spring Boot 4.1 line on Java 17, 21 and 25. See
[docs/compatibility.md](docs/compatibility.md).

## License

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
