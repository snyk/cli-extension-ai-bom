package code

type SarifMessage struct {
	Text string `json:"text"`
}

type SarifResult struct {
	Message SarifMessage `json:"message"`
}

type SarifRun struct {
	Results []SarifResult `json:"results"`
}

type Sarif struct {
	Runs []SarifRun `json:"runs"`
}
