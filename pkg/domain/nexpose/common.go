package nexpose

// Configuration represents a name-value pair
type Configuration struct {
	// The name of the configuration value.
	Name string `json:"name"`
	// The configuration value.
	Value string `json:"value,omitempty"`
}

// Link represents a hyperlink and relation
type Link struct {
	// A hypertext reference.
	Href string `json:"href,omitempty"`
	// The link relation type.
	Rel string `json:"rel,omitempty"`
}
