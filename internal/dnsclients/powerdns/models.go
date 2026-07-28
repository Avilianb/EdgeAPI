package powerdns

type Zone struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Kind           string  `json:"kind"`
	RRSets         []RRSet `json:"rrsets"`
	URL            string  `json:"url"`
	Serial         uint32  `json:"serial"`
	NotifiedSerial uint32  `json:"notified_serial"`
}

type RRSet struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	TTL        int32     `json:"ttl,omitempty"`
	ChangeType string    `json:"changetype,omitempty"`
	Records    []Record  `json:"records,omitempty"`
	Comments   []Comment `json:"comments,omitempty"`
}

type Record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type Comment struct {
	Content    string `json:"content"`
	Account    string `json:"account"`
	ModifiedAt int64  `json:"modified_at"`
}

type PatchZoneRequest struct {
	RRSets []RRSet `json:"rrsets"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
