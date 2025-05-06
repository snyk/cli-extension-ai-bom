package flags

import "github.com/spf13/pflag"

const (
	FlagSetName                = "snyk-cli-extension-ai-bom"
	FlagExperimental           = "experimental"
	FlagCodeAPIURL             = "code-api-url"
	FlagFilesBundlestoreAPIURL = "filesbundlestore-api-url"
)

func GetAiBBomFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet(FlagSetName, pflag.ExitOnError)
	flagSet.Bool(FlagExperimental, false, "This is an experiment feature that will contain breaking changes in future revisions")
	flagSet.String(FlagCodeAPIURL, "", "If set override the url of the code service to be used")
	flagSet.String(FlagFilesBundlestoreAPIURL, "", "If set override the url of the files bundle store service to be used")
	return flagSet
}
