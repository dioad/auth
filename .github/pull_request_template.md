## Description
Brief description of the changes made in this PR.

## Related Issues
Closes #(issue number) or relates to #(issue number).

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Dependency update

## Changes Made
Describe the specific changes:
- Change 1
- Change 2
- Change 3

## Testing
Describe how you tested these changes:
- [ ] Added new tests
- [ ] Updated existing tests
- [ ] All existing tests still pass
- [ ] Tested with `go test -race ./...`
- [ ] Manual testing (describe below)

### Test Results
```
[paste test output or describe manual testing]
```

## Code Quality Checklist
- [ ] Code follows project style guidelines (gofmt, go vet)
- [ ] All exported types/functions have Godoc comments
- [ ] No new warnings from `go vet ./...`
- [ ] All tests pass with `go test -race ./...`
- [ ] No hardcoded secrets or sensitive information
- [ ] Proper error handling with wrapped errors (`fmt.Errorf` with `%w`)
- [ ] Context.Context is passed to I/O operations
- [ ] No breaking changes to public APIs (or breaking change is documented)

## Documentation
- [ ] Updated README.md (if applicable)
- [ ] Updated AGENTS.md (if applicable)
- [ ] Added code examples (if applicable)
- [ ] Added/updated Godoc comments (if applicable)

## Performance Impact
Does this change impact performance?
- [ ] No performance impact
- [ ] Improved performance (describe)
- [ ] Potential performance impact (describe mitigation)

## Additional Notes
Add any other context or notes that reviewers should know:
