package prompts

import _ "embed"

//go:embed security_audit.md
var SecurityAudit string

//go:embed validator_instructions.md
var ValidatorInstructions string

//go:embed autofixer_instructions.md
var AutofixerInstructions string
