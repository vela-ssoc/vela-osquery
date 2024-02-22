package osquery

import (
	"github.com/osquery/osquery-go"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/vela"
	"time"
)

var (
	xEnv vela.Environment
)

/*
	local cli = rock.osquery{
		name  = "osq",
		path  = "share/software/osqueryd",
		flags = {"a=123" , "bb=456" , "xx==789"}
	}
	cli.start()

	local rx = cli.query("select * from aa")
*/

func osqueryL(L *lua.LState) int {
	s := NewOsquery()
	if e := s.DetectAndInstall(); e != nil {
		L.RaiseError("detect and install osquery fail %v", e)
		return 0
	}

	cli, err := osquery.NewClient(ExtensionsSocket, 30*time.Second)
	if err != nil {
		L.Push(newReply(nil, err))
		return 1
	}
	r, err := cli.Query(L.CheckString(1))
	v := newReply(r, err)
	L.Push(v)
	return 1
}

func startupL(L *lua.LState) int {
	s := NewOsquery()
	e := s.DetectAndInstall()
	if e != nil {
		L.RaiseError("detect and install osquery fail %v", e)
	}
	return 0
}

func WithEnv(env vela.Environment) {
	xEnv = env
	define(xEnv.R())
	kv := lua.NewUserKV()
	kv.Set("startup", lua.NewFunction(startupL))
	xEnv.Set("osquery", lua.NewExport("vela.osquery.export", lua.WithFunc(osqueryL), lua.WithTable(kv)))
}

//vela.osquery("select * from arp_cache").pipe()

/*
	local r = vela.osquery()

	r.pipe(arg , [name] , [force]) --
	r.keys() --
	r.

*/
