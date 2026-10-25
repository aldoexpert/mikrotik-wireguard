package handler

import "net/http"

// ControllerMethod is the signature every registered module/controller/method
// endpoint must implement. params holds the extra URL segments after
// module/controller/method, e.g. /wireguard/clients/get/<id> -> params[0] == id.
type ControllerMethod func(w http.ResponseWriter, r *http.Request, params []string)
