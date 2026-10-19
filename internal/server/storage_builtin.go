package server

import (
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	"github.com/onegreyonewhite/easyrest/plugins/storage/dbglob"
	"github.com/onegreyonewhite/easyrest/plugins/storage/local"
	"github.com/onegreyonewhite/easyrest/plugins/storage/memory"
	"github.com/onegreyonewhite/easyrest/plugins/storage/static"
)

func registerBuiltinStoragePlugins() {
	PreservedStoragePlugins["local"] = func() easyrest.StoragePlugin { return local.New() }
	PreservedStoragePlugins["memory"] = func() easyrest.StoragePlugin { return memory.New() }
	PreservedStoragePlugins["dbglob"] = func() easyrest.StoragePlugin { return dbglob.New() }
	PreservedStoragePlugins["static"] = func() easyrest.StoragePlugin { return static.New() }
}
