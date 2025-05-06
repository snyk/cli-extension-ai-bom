package flags_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-ai-bom/internal/flags"
)

func TestGetAiBomFlagSet(t *testing.T) {
	flagSet := flags.GetAiBBomFlagSet()

	tc := []struct {
		flagName string
		isBool   bool
		expected interface{}
	}{
		{
			flagName: flags.FlagExperimental,
			isBool:   true,
			expected: false,
		},
		{
			flagName: flags.FlagCodeAPIURL,
			isBool:   false,
			expected: "",
		},
		{
			flagName: flags.FlagFilesBundlestoreAPIURL,
			isBool:   false,
			expected: "",
		},
	}

	for _, tt := range tc {
		t.Run(tt.flagName, func(t *testing.T) {
			var val interface{}
			var err error

			if tt.isBool {
				val, err = flagSet.GetBool(tt.flagName)
			} else {
				val, err = flagSet.GetString(tt.flagName)
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, val)
		})
	}
}
