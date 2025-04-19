### Unreleased

* Update selinux to 6f8f496eabd35f28dfa6b4be5fc82e325e1df620 to fix compilation with C23
* Update dependencies

### Version 0.3.2

* Update dependencies

### Version 0.3.1

* Only allow setting xperm rules if the policy version supports it
* Update dependencies

### Version 0.3.0

* Use byte arrays instead of Read/Write traits when parsing and writing policies

### Version 0.2.0

* Add support for creating auditallow and dontaudit rules

### Version 0.1.2

* Revert clang_rt x86_64 change and move it to cargo-android instead

### Version 0.1.1

* Explicitly link NDK's clang_rt on x86_64

### Version 0.1.0

* Initial release
