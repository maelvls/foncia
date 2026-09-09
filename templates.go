package main

import _ "embed"

// The HTML lives in templates/ rather than in Go string literals so that
// editors syntax-highlight it and so that a stray backquote can't break the
// build.

//go:embed templates/header.html
var headerHTML string

//go:embed templates/index.html
var indexHTML string

//go:embed templates/error.html
var errorHTML string

//go:embed templates/coowners.html
var coownersHTML string
