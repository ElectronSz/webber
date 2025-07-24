Contributing to Webber
We welcome and appreciate all contributions to the Webber Web Server! Whether you're fixing a bug, adding a new feature, improving documentation, or suggesting an idea, your efforts help make Webber better for everyone.

Please take a moment to review this document to understand how to contribute effectively.

Table of Contents
Reporting Bugs

Suggesting Enhancements

Setting Up Your Development Environment

Making a Pull Request

Coding Style

Running Tests

Code of Conduct

1. Reporting Bugs
If you find a bug in Webber, please help us by reporting it!

Check existing issues: Before opening a new issue, please search the issue tracker to see if the bug has already been reported.

Provide detailed information: When reporting a bug, include as much detail as possible:

Steps to reproduce: A clear, step-by-step description of how to trigger the bug.

Expected behavior: What you expected to happen.

Actual behavior: What actually happened.

Webber version: The version of Webber you are using (e.g., v1.0.0).

Go version: Your Go compiler version (go version).

Operating System: (e.g., Ubuntu 22.04, macOS Ventura).

Relevant logs: Any output from journalctl -u webber or console errors.

Configuration: Your config.json (redact any sensitive information).

2. Suggesting Enhancements
Have an idea for a new feature or an improvement to an existing one? We'd love to hear it!

Check existing issues: Search the issue tracker to see if your idea has already been discussed.

Describe your idea: Clearly explain the enhancement, why it would be useful, and how you envision it working. Providing a use case or scenario helps a lot.

3. Setting Up Your Development Environment
To contribute code, you'll need a Go development environment.

Install Go: If you don't have Go installed, follow the official instructions: https://go.dev/doc/install

Clone the repository:

git clone https://github.com/ElectronSz/webber.git
cd webber

Build the binary:

go build -o webber main.go

This will create an executable named webber in your current directory.

Run locally (for testing):
You can run Webber locally using a test configuration. Create a config.json in the root of your project for development purposes.

./webber -config ./config.json

(Note: The install.sh script sets up the server to run from /etc/webber/config.json and /var/www/webber, but for development, you'll likely want to use local paths.)

4. Making a Pull Request
When you're ready to submit your code changes:

Fork the repository: Fork the ElectronSz/webber repository on GitHub.

Create a new branch:

git checkout -b feature/your-feature-name # for new features
# or
git checkout -b bugfix/issue-number-description # for bug fixes

Make your changes: Implement your feature or fix the bug.

Write tests: If you've added new functionality or fixed a bug, please write appropriate tests to cover your changes.

Run tests: Ensure all existing tests pass and your new tests pass. See Running Tests.

Commit your changes: Write clear, concise commit messages. A good commit message explains what was changed and why.

git commit -m "feat: Add new awesome feature"
# or
git commit -m "fix: Resolve issue #123 with X"

Push to your fork:

git push origin feature/your-feature-name

Open a Pull Request (PR): Go to the original ElectronSz/webber repository on GitHub and open a new pull request from your branch.

Reference issues: Link your PR to any relevant issues (e.g., "Closes #123" or "Fixes #456").

Describe your changes: Provide a clear description of your changes, including why they were made and any relevant context.

Screenshots/demos: If your changes involve UI or visible behavior, include screenshots or a short GIF.

5. Coding Style
Webber follows standard Go coding conventions.

gofmt: Always run gofmt on your code before committing.

go fmt ./...

golint / go vet: Consider running golint and go vet to catch common issues.

go vet ./...

Clarity and Readability: Write clear, readable, and well-commented code.

Error Handling: Go emphasizes explicit error handling. Ensure errors are handled appropriately and returned when necessary.

6. Running Tests
Webber uses Go's built-in testing framework.

Run all tests:

go test ./...

Run tests with verbose output:

go test -v ./...

Run specific test file:

go test ./path/to/your_package_test.go

7. Code of Conduct
Please note that this project is released with a Contributor Code of Conduct. By participating in this project, you agree to abide by its terms. We are committed to fostering an open and welcoming environment.

Thank you for contributing to Webber!
