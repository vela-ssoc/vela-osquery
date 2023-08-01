package osquery

import (
	"encoding/json"
	"fmt"
	"github.com/valyala/fasthttp"
	"github.com/vela-ssoc/vela-kit/vela"
)

func define(r vela.Router) {
	r.POST("/api/v1/arr/agent/osquery/query", xEnv.Then(func(ctx *fasthttp.RequestCtx) error {
		s := ctx.Request.Body()
		v := query(string(s))
		if v.Err != nil {
			return v.Err
		}

		if v.Status != nil && v.Status.Code != 0 {
			return fmt.Errorf("%s", v.Status.Message)
		}

		chunk, _ := json.Marshal(v.Body)
		ctx.Write(chunk)
		return nil
	}))
}
