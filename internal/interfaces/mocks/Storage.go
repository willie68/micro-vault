// Code generated by mockery v2.14.0. DO NOT EDIT.

package mocks

import (
	mock "github.com/stretchr/testify/mock"
	model "github.com/willie68/micro-vault/internal/model"
)

// Storage is an autogenerated mock type for the Storage type
type Storage struct {
	mock.Mock
}

type Storage_Expecter struct {
	mock *mock.Mock
}

func (_m *Storage) EXPECT() *Storage_Expecter {
	return &Storage_Expecter{mock: &_m.Mock}
}

// AddClient provides a mock function with given fields: c
func (_m *Storage) AddClient(c model.Client) (string, error) {
	ret := _m.Called(c)

	var r0 string
	if rf, ok := ret.Get(0).(func(model.Client) string); ok {
		r0 = rf(c)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(model.Client) error); ok {
		r1 = rf(c)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Storage_AddClient_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddClient'
type Storage_AddClient_Call struct {
	*mock.Call
}

// AddClient is a helper method to define mock.On call
//  - c model.Client
func (_e *Storage_Expecter) AddClient(c interface{}) *Storage_AddClient_Call {
	return &Storage_AddClient_Call{Call: _e.mock.On("AddClient", c)}
}

func (_c *Storage_AddClient_Call) Run(run func(c model.Client)) *Storage_AddClient_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(model.Client))
	})
	return _c
}

func (_c *Storage_AddClient_Call) Return(_a0 string, _a1 error) *Storage_AddClient_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

// AddGroup provides a mock function with given fields: g
func (_m *Storage) AddGroup(g model.Group) (string, error) {
	ret := _m.Called(g)

	var r0 string
	if rf, ok := ret.Get(0).(func(model.Group) string); ok {
		r0 = rf(g)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(model.Group) error); ok {
		r1 = rf(g)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Storage_AddGroup_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddGroup'
type Storage_AddGroup_Call struct {
	*mock.Call
}

// AddGroup is a helper method to define mock.On call
//  - g model.Group
func (_e *Storage_Expecter) AddGroup(g interface{}) *Storage_AddGroup_Call {
	return &Storage_AddGroup_Call{Call: _e.mock.On("AddGroup", g)}
}

func (_c *Storage_AddGroup_Call) Run(run func(g model.Group)) *Storage_AddGroup_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(model.Group))
	})
	return _c
}

func (_c *Storage_AddGroup_Call) Return(id string, err error) *Storage_AddGroup_Call {
	_c.Call.Return(id, err)
	return _c
}

// CreateClient provides a mock function with given fields: n, g
func (_m *Storage) CreateClient(n string, g []string) (*model.Client, error) {
	ret := _m.Called(n, g)

	var r0 *model.Client
	if rf, ok := ret.Get(0).(func(string, []string) *model.Client); ok {
		r0 = rf(n, g)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Client)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, []string) error); ok {
		r1 = rf(n, g)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Storage_CreateClient_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateClient'
type Storage_CreateClient_Call struct {
	*mock.Call
}

// CreateClient is a helper method to define mock.On call
//  - n string
//  - g []string
func (_e *Storage_Expecter) CreateClient(n interface{}, g interface{}) *Storage_CreateClient_Call {
	return &Storage_CreateClient_Call{Call: _e.mock.On("CreateClient", n, g)}
}

func (_c *Storage_CreateClient_Call) Run(run func(n string, g []string)) *Storage_CreateClient_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].([]string))
	})
	return _c
}

func (_c *Storage_CreateClient_Call) Return(_a0 *model.Client, _a1 error) *Storage_CreateClient_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

// DeleteClient provides a mock function with given fields: a
func (_m *Storage) DeleteClient(a string) (bool, error) {
	ret := _m.Called(a)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string) bool); ok {
		r0 = rf(a)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(a)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Storage_DeleteClient_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteClient'
type Storage_DeleteClient_Call struct {
	*mock.Call
}

// DeleteClient is a helper method to define mock.On call
//  - a string
func (_e *Storage_Expecter) DeleteClient(a interface{}) *Storage_DeleteClient_Call {
	return &Storage_DeleteClient_Call{Call: _e.mock.On("DeleteClient", a)}
}

func (_c *Storage_DeleteClient_Call) Run(run func(a string)) *Storage_DeleteClient_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *Storage_DeleteClient_Call) Return(ok bool, err error) *Storage_DeleteClient_Call {
	_c.Call.Return(ok, err)
	return _c
}

// DeleteGroup provides a mock function with given fields: n
func (_m *Storage) DeleteGroup(n string) (bool, error) {
	ret := _m.Called(n)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string) bool); ok {
		r0 = rf(n)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(n)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Storage_DeleteGroup_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteGroup'
type Storage_DeleteGroup_Call struct {
	*mock.Call
}

// DeleteGroup is a helper method to define mock.On call
//  - n string
func (_e *Storage_Expecter) DeleteGroup(n interface{}) *Storage_DeleteGroup_Call {
	return &Storage_DeleteGroup_Call{Call: _e.mock.On("DeleteGroup", n)}
}

func (_c *Storage_DeleteGroup_Call) Run(run func(n string)) *Storage_DeleteGroup_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *Storage_DeleteGroup_Call) Return(ok bool, err error) *Storage_DeleteGroup_Call {
	_c.Call.Return(ok, err)
	return _c
}

// GetClient provides a mock function with given fields: a
func (_m *Storage) GetClient(a string) (*model.Client, bool) {
	ret := _m.Called(a)

	var r0 *model.Client
	if rf, ok := ret.Get(0).(func(string) *model.Client); ok {
		r0 = rf(a)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Client)
		}
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(string) bool); ok {
		r1 = rf(a)
	} else {
		r1 = ret.Get(1).(bool)
	}

	return r0, r1
}

// Storage_GetClient_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetClient'
type Storage_GetClient_Call struct {
	*mock.Call
}

// GetClient is a helper method to define mock.On call
//  - a string
func (_e *Storage_Expecter) GetClient(a interface{}) *Storage_GetClient_Call {
	return &Storage_GetClient_Call{Call: _e.mock.On("GetClient", a)}
}

func (_c *Storage_GetClient_Call) Run(run func(a string)) *Storage_GetClient_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *Storage_GetClient_Call) Return(_a0 *model.Client, _a1 bool) *Storage_GetClient_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

// GetGroup provides a mock function with given fields: n
func (_m *Storage) GetGroup(n string) (*model.Group, bool) {
	ret := _m.Called(n)

	var r0 *model.Group
	if rf, ok := ret.Get(0).(func(string) *model.Group); ok {
		r0 = rf(n)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Group)
		}
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(string) bool); ok {
		r1 = rf(n)
	} else {
		r1 = ret.Get(1).(bool)
	}

	return r0, r1
}

// Storage_GetGroup_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetGroup'
type Storage_GetGroup_Call struct {
	*mock.Call
}

// GetGroup is a helper method to define mock.On call
//  - n string
func (_e *Storage_Expecter) GetGroup(n interface{}) *Storage_GetGroup_Call {
	return &Storage_GetGroup_Call{Call: _e.mock.On("GetGroup", n)}
}

func (_c *Storage_GetGroup_Call) Run(run func(n string)) *Storage_GetGroup_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *Storage_GetGroup_Call) Return(_a0 *model.Group, _a1 bool) *Storage_GetGroup_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

// GetGroups provides a mock function with given fields:
func (_m *Storage) GetGroups() ([]model.Group, error) {
	ret := _m.Called()

	var r0 []model.Group
	if rf, ok := ret.Get(0).(func() []model.Group); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.Group)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Storage_GetGroups_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetGroups'
type Storage_GetGroups_Call struct {
	*mock.Call
}

// GetGroups is a helper method to define mock.On call
func (_e *Storage_Expecter) GetGroups() *Storage_GetGroups_Call {
	return &Storage_GetGroups_Call{Call: _e.mock.On("GetGroups")}
}

func (_c *Storage_GetGroups_Call) Run(run func()) *Storage_GetGroups_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Storage_GetGroups_Call) Return(_a0 []model.Group, _a1 error) *Storage_GetGroups_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

// HasClient provides a mock function with given fields: n
func (_m *Storage) HasClient(n string) bool {
	ret := _m.Called(n)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string) bool); ok {
		r0 = rf(n)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// Storage_HasClient_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HasClient'
type Storage_HasClient_Call struct {
	*mock.Call
}

// HasClient is a helper method to define mock.On call
//  - n string
func (_e *Storage_Expecter) HasClient(n interface{}) *Storage_HasClient_Call {
	return &Storage_HasClient_Call{Call: _e.mock.On("HasClient", n)}
}

func (_c *Storage_HasClient_Call) Run(run func(n string)) *Storage_HasClient_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *Storage_HasClient_Call) Return(_a0 bool) *Storage_HasClient_Call {
	_c.Call.Return(_a0)
	return _c
}

// HasGroup provides a mock function with given fields: n
func (_m *Storage) HasGroup(n string) bool {
	ret := _m.Called(n)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string) bool); ok {
		r0 = rf(n)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// Storage_HasGroup_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HasGroup'
type Storage_HasGroup_Call struct {
	*mock.Call
}

// HasGroup is a helper method to define mock.On call
//  - n string
func (_e *Storage_Expecter) HasGroup(n interface{}) *Storage_HasGroup_Call {
	return &Storage_HasGroup_Call{Call: _e.mock.On("HasGroup", n)}
}

func (_c *Storage_HasGroup_Call) Run(run func(n string)) *Storage_HasGroup_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *Storage_HasGroup_Call) Return(_a0 bool) *Storage_HasGroup_Call {
	_c.Call.Return(_a0)
	return _c
}

// Init provides a mock function with given fields:
func (_m *Storage) Init() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Storage_Init_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Init'
type Storage_Init_Call struct {
	*mock.Call
}

// Init is a helper method to define mock.On call
func (_e *Storage_Expecter) Init() *Storage_Init_Call {
	return &Storage_Init_Call{Call: _e.mock.On("Init")}
}

func (_c *Storage_Init_Call) Run(run func()) *Storage_Init_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Storage_Init_Call) Return(_a0 error) *Storage_Init_Call {
	_c.Call.Return(_a0)
	return _c
}

// ListClients provides a mock function with given fields: c
func (_m *Storage) ListClients(c func(model.Client) bool) error {
	ret := _m.Called(c)

	var r0 error
	if rf, ok := ret.Get(0).(func(func(model.Client) bool) error); ok {
		r0 = rf(c)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Storage_ListClients_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListClients'
type Storage_ListClients_Call struct {
	*mock.Call
}

// ListClients is a helper method to define mock.On call
//  - c func(model.Client) bool
func (_e *Storage_Expecter) ListClients(c interface{}) *Storage_ListClients_Call {
	return &Storage_ListClients_Call{Call: _e.mock.On("ListClients", c)}
}

func (_c *Storage_ListClients_Call) Run(run func(c func(model.Client) bool)) *Storage_ListClients_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(func(model.Client) bool))
	})
	return _c
}

func (_c *Storage_ListClients_Call) Return(_a0 error) *Storage_ListClients_Call {
	_c.Call.Return(_a0)
	return _c
}

type mockConstructorTestingTNewStorage interface {
	mock.TestingT
	Cleanup(func())
}

// NewStorage creates a new instance of Storage. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewStorage(t mockConstructorTestingTNewStorage) *Storage {
	mock := &Storage{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
