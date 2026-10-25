package core

// MenuItem is one link in the frontend navigation menu.
type MenuItem struct {
	Link  string `json:"link"`
	Label string `json:"label"`
	Admin bool   `json:"admin,omitempty"`
}

// MenuGroup is a labelled group of MenuItem contributed by a module.
type MenuGroup struct {
	Header string     `json:"header"`
	Icon   string     `json:"icon"`
	List   []MenuItem `json:"list"`
}
