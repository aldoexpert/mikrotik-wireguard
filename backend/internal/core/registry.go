package core

import (
	"fmt"

	"github.com/aldoexpert/mikrotik-wireguard/internal/handler"
)

// Controller is implemented by every module controller.
type Controller interface{}

// ControllerMethod is an alias for handler.ControllerMethod.
type ControllerMethod = handler.ControllerMethod

// Registry stores the module/controller/method -> handler mapping.
type Registry struct {
	controllers map[string]Controller
	methods     map[string]ControllerMethod
	menus       []MenuGroup
}

// NewRegistry creates a new, empty registry.
func NewRegistry() *Registry {
	return &Registry{
		controllers: make(map[string]Controller),
		methods:     make(map[string]ControllerMethod),
		menus:       []MenuGroup{},
	}
}

// RegisterController registers a controller instance under module.name.
func (r *Registry) RegisterController(module, name string, controller Controller) {
	key := fmt.Sprintf("%s.%s", module, name)
	r.controllers[key] = controller
}

// RegisterMethod registers an endpoint handler under module.controller.method.
func (r *Registry) RegisterMethod(module, controller, method string, h ControllerMethod) {
	key := fmt.Sprintf("%s.%s.%s", module, controller, method)
	r.methods[key] = h
}

// GetMethod looks up a registered endpoint handler.
func (r *Registry) GetMethod(module, controller, method string) (ControllerMethod, bool) {
	key := fmt.Sprintf("%s.%s.%s", module, controller, method)
	h, exists := r.methods[key]
	return h, exists
}

// GetController looks up a registered controller instance.
func (r *Registry) GetController(module, name string) (Controller, bool) {
	key := fmt.Sprintf("%s.%s", module, name)
	controller, exists := r.controllers[key]
	return controller, exists
}

// RegisterMenu registers one navigation menu group contributed by a module.
func (r *Registry) RegisterMenu(group MenuGroup) {
	r.menus = append(r.menus, group)
}

// GetMenus returns every registered navigation menu group.
func (r *Registry) GetMenus() []MenuGroup {
	return r.menus
}
