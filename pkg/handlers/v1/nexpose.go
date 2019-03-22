package v1

type AssetSearchRequestBody struct {
	Match string
	Filters Filters
}

type Filters struct {
	Field string
	Lower string
	Operator string
	Upper string
	Value string
	Values []string
}

type AssetSearchResponseBody struct {
	Links []interface{}
	Page AssetSearchPage
	Resources AssetSearchResources
}

type AssetSearchPage struct {
	Number int64
	Size int64
	TotalPages int64
	TotalResources int64
}

type AssetSearchResources struct {
	Addresses []interface{}
	AssessedForPolicies bool
	AssessedForVulnerabilities bool
	Configurations []interface{}
	Databases []interface{}
	Files []interface{}
	History []interface{}
	HostName string
	HostNames []interface{}
 	ID int64
	IDs []interface{}
	IP string
	Links []interface{}
	Mac string
	OS string
	OSFingerprint float64
	RawRiskScore float64
	Services []interface{}
	Software []interface{}
	Type string
	UserGroups []interface{}
	Users []interface{}
	Vulnerabilities AssetSearchVulnerabilities
}

type AssetSearchVulnerabilities struct {
	Critical int64
	Exploits int64
	MalwareKits int64
	Moderate int64
	Severe int64
	Total int64
}

type AssetVulnRequestBody struct {

}

type AssetVulnResponse struct {
	Links []interface{}
	Page AssetSearchPage
	Resources AssetVulnResources
}

type AssetVulnResources struct {
	ID string
	Instances int32
	Links []interface{}
	Results
}