package nexpose

import (
	"os"
)

// Asset represents a Nexpose asset response payload
// See: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteAssets
type Asset struct {
	// All addresses discovered on the asset.
	Addresses []Address `json:"addresses,omitempty"`
	// Whether the asset has been assessed for policies at least once.
	AssessedForPolicies bool `json:"assessedForPolicies,omitempty"`
	// Whether the asset has been assessed for vulnerabilities at least once.
	AssessedForVulnerabilities bool `json:"assessedForVulnerabilities,omitempty"`
	// Configuration key-values pairs enumerated on the asset.
	Configurations []Configuration `json:"configurations,omitempty"`
	// The databases enumerated on the asset.
	Databases []Database `json:"databases,omitempty"`
	// The files discovered with searching on the asset.
	Files []*os.File `json:"files,omitempty"`
	// The history of changes to the asset over time.
	History []AssetHistory `json:"history,omitempty"`
	// The primary host name (local or FQDN) of the asset.
	HostName string `json:"hostName,omitempty"`
	// All host names or aliases discovered on the asset.
	HostNames []HostName `json:"hostNames,omitempty"`
	// The identifier of the asset.
	ID int64 `json:"id,omitempty"`
	// Unique identifiers found on the asset, such as hardware or operating system identifiers.
	IDs []UniqueID `json:"ids,omitempty"`
	// The primary IPv4 or IPv6 address of the asset.
	IP string `json:"ip,omitempty"`
	// Hypermedia links to corresponding or related resources.
	Links []Link `json:"links,omitempty"`
	// The primary Media Access Control (MAC) address of the asset. The format is six groups of two hexadecimal digits separated by colons.
	Mac string `json:"mac,omitempty"`
	// The full description of the operating system of the asset.
	OS string `json:"os,omitempty"`
	// The details of the operating system of the asset.
	OSFingerprint *OperatingSystem `json:"osFingerprint,omitempty"`
	// The base risk score of the asset.
	RawRiskScore float64 `json:"rawRiskScore,omitempty"`
	// The risk score (with criticality adjustments) of the asset.
	RiskScore float64 `json:"riskScore,omitempty"`
	// The services discovered on the asset.
	Services []Service `json:"services,omitempty"`
	// The software discovered on the asset.
	Software []Software `json:"software,omitempty"`
	// The type of asset.
	Type string `json:"type,omitempty"`
	// The group accounts enumerated on the asset.
	UserGroups []GroupAccount `json:"userGroups,omitempty"`
	// The user accounts enumerated on the asset.
	Users []UserAccount `json:"users,omitempty"`
	// Summary information for vulnerabilities on the asset.
	VulnerabilitiesSummary *VulnerabilitySummary `json:"vulnerabilities,omitempty"`
}

// Address represents the Address field of a Nexpose asset
type Address struct {
	// The IPv4 or IPv6 address.
	IP string `json:"ip,omitempty"`
	// The Media Access Control (MAC) address. The format is six groups of two hexadecimal digits separated by colons.
	Mac string `json:"mac,omitempty"`
}

// Database represents associated databases
type Database struct {
	// The description of the database instance.
	Description string `json:"description,omitempty"`
	// The identifier of the database.
	ID int32 `json:"id,omitempty"`
	// The name of the database instance.
	Name string `json:"name"`
}

// AssetHistory represents a change to the asset
type AssetHistory struct { // The date the asset information was collected or changed.
	Date string `json:"date,omitempty"`
	// Additional information describing the change.
	Description string `json:"description,omitempty"`
	// If a scan-oriented change, the identifier of the corresponding scan the asset was scanned in.
	ScanID int64 `json:"scanId,omitempty"`
	// The type of change
	Type string `json:"type,omitempty"`
	// If a vulnerability exception change, the login name of the user that performed the operation.
	User string `json:"user,omitempty"`
	// The version number of the change (a chronological incrementing number starting from 1).
	Version int32 `json:"version,omitempty"`
	// If a vulnerability exception change, the identifier of the vulnerability exception that caused the change.
	VulnerabilityExceptionID int32 `json:"vulnerabilityExceptionId,omitempty"`
}

// HostName represents a hostname of an asset and where it is sourced
type HostName struct {
	// The host name (local or FQDN).
	Name string `json:"name"`
	// The source used to detect the host name. `user` indicates the host name source is user-supplied (e.g. in a site target definition).
	Source string `json:"source,omitempty"`
}

// UniqueID represents unique identifiers associated with an asset
type UniqueID struct {
	// The unique identifier.
	ID string `json:"id"`
	// The source of the unique identifier.
	Source string `json:"source,omitempty"`
}

// OperatingSystem represents operating system details
type OperatingSystem struct {
	// The architecture of the operating system.
	Architecture string `json:"architecture,omitempty"`
	// Configuration key-values pairs enumerated on the operating system.
	Configurations []Configuration `json:"configurations,omitempty"`
	// The Common Platform Enumeration (CPE) of the operating system.
	CPE *CPE `json:"cpe,omitempty"`
	// The description of the operating system (containing vendor, family, product, version and architecture in a single string).
	Description string `json:"description,omitempty"`
	// The family of the operating system.
	Family string `json:"family,omitempty"`
	// The identifier of the operating system.
	ID int64 `json:"id,omitempty"`
	// The name of the operating system.
	Product string `json:"product,omitempty"`
	// A combination of vendor and family (with redundancies removed), suitable for grouping.
	SystemName string `json:"systemName,omitempty"`
	// The type of operating system.
	Type string `json:"type,omitempty"`
	// The vendor of the operating system.
	Vendor string `json:"vendor,omitempty"`
	// The version of the operating system.
	Version string `json:"version,omitempty"`
}

// Service represents a service on an Asset
type Service struct {
	// Configuration key-values pairs enumerated on the service.
	Configurations []Configuration `json:"configurations,omitempty"`
	// The databases enumerated on the service.
	Databases []Database `json:"databases,omitempty"`
	// The family of the service.
	Family string `json:"family,omitempty"`
	// Hypermedia links to corresponding or related resources.
	Links []Link `json:"links,omitempty"`
	// The name of the service.
	Name string `json:"name,omitempty"`
	// The port of the service.
	Port int32 `json:"port"`
	// The product running the service.
	Product string `json:"product,omitempty"`
	// The protocol of the service.
	Protocol string `json:"protocol"`
	// The group accounts enumerated on the service.
	UserGroups []GroupAccount `json:"userGroups,omitempty"`
	// The user accounts enumerated on the service.
	Users []UserAccount `json:"users,omitempty"`
	// The vendor of the service.
	Vendor string `json:"vendor,omitempty"`
	// The version of the service.
	Version string `json:"version,omitempty"`
	// The web applications found on the service.
	WebApplications []WebApplication `json:"webApplications,omitempty"`
}

// GroupAccount represents a group account associated with an Asset or Service
type GroupAccount struct {
	// The identifier of the user group.
	ID int32 `json:"id,omitempty"`
	// The name of the user group.
	Name string `json:"name"`
}

// UserAccount represents a user associated with an Asset or Service
type UserAccount struct {
	// The full name of the user account.
	FullName string `json:"fullName,omitempty"`
	// The identifier of the user account.
	ID int32 `json:"id,omitempty"`
	// The name of the user account.
	Name string `json:"name"`
}

// WebApplication represents a web application associated with a Service
type WebApplication struct {
	// The identifier of the web application.
	ID int64 `json:"id,omitempty"`
	// The pages discovered on the web application.
	Pages []WebPage `json:"pages,omitempty"`
	// The web root of the web application.
	Root string `json:"root,omitempty"`
	// The virtual host of the web application.
	VirtualHost string `json:"virtualHost,omitempty"`
}

// WebPage represents a page found within a WebApplication
type WebPage struct {
	// The type of link used to traverse or detect the page.
	LinkType string `json:"linkType,omitempty"`
	// The path to the page (URI).
	Path string `json:"path,omitempty"`
	// The HTTP response code observed with retrieving the page.
	Response int32 `json:"response,omitempty"`
}

// Software represents the software discovered on an Asset
type Software struct {
	// ${software.attributes.description}
	Configurations []Configuration `json:"configurations,omitempty"`
	// The Common Platform Enumeration (CPE) of the software.
	CPE *CPE `json:"cpe,omitempty"`
	// The description of the software.
	Description string `json:"description,omitempty"`
	// The family of the software.
	Family string `json:"family,omitempty"`
	ID     int64  `json:"id,omitempty"`
	// The product of the software.
	Product string `json:"product,omitempty"`
	// The version of the software.
	Type string `json:"type,omitempty"`
	// The vendor of the software.
	Vendor string `json:"vendor,omitempty"`
	// The version of the software.
	Version string `json:"version,omitempty"`
}

// CPE represents the Common Platform Enumeration (CPE) of the operating system or software
type CPE struct {
	// Edition-related terms applied by the vendor to the product.
	Edition string `json:"edition,omitempty"`
	// Defines the language supported in the user interface of the product being described. The format is of the language tag adheres to <a target=\"_blank\" href=\"https://tools.ietf.org/html/rfc5646\">RFC5646</a>.
	Language string `json:"language,omitempty"`
	// Captures any other general descriptive or identifying information which is vendor- or product-specific and which does not logically fit in any other attribute value.
	Other string `json:"other,omitempty"`
	// A single letter code that designates the particular platform part that is being identified.
	Part string `json:"part"`
	// the most common and recognizable title or name of the product.
	Product string `json:"product,omitempty"`
	// Characterizes how the product is tailored to a particular market or class of end users.
	SwEdition string `json:"swEdition,omitempty"`
	// Characterize the instruction set architecture on which the product operates.
	TargetHW string `json:"targetHW,omitempty"`
	// Characterize the software computing environment within which the product operates.
	TargetSW string `json:"targetSW,omitempty"`
	// Vendor-specific alphanumeric strings characterizing the particular update, service pack, or point release of the product.
	Update string `json:"update,omitempty"`
	// The full CPE string in the <a target=\"_blank\" href=\"https://cpe.mitre.org/files/cpe-specification_2.2.pdf\">CPE 2.2</a> format.
	V22 string `json:"v2.2,omitempty"`
	// The full CPE string in the <a target=\"_blank\" href=\"http://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf\">CPE 2.3</a> format.
	V23 string `json:"v2.3,omitempty"`
	// The person or organization that manufactured or created the product.
	Vendor string `json:"vendor,omitempty"`
	// Vendor-specific alphanumeric strings characterizing the particular release version of the product.
	Version string `json:"version,omitempty"`
}

// VulnerabilitySummary is a tally of the types of vulnerabilities detected on an Asset
type VulnerabilitySummary struct {
	// The number of critical vulnerabilities.
	Critical int64 `json:"critical,omitempty"`
	// The number of distinct exploits that can exploit any of the vulnerabilities on the asset.
	Exploits int64 `json:"exploits,omitempty"`
	// The number of distinct malware kits that vulnerabilities on the asset are susceptible to.
	MalwareKits int64 `json:"malwareKits,omitempty"`
	// The number of moderate vulnerabilities.
	Moderate int64 `json:"moderate,omitempty"`
	// The number of severe vulnerabilities.
	Severe int64 `json:"severe,omitempty"`
	// The total number of vulnerabilities.
	Total int64 `json:"total,omitempty"`
}
