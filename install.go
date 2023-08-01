package osquery

import (
	"fmt"
	"github.com/osquery/osquery-go"
	"github.com/vela-ssoc/vela-kit/exception"
	ps "github.com/vela-ssoc/vela-process"
	"os"
	"time"
)

func (s *Service) Ok() bool {
	if _, err := os.Stat(ExtensionsSocket); err == nil {
		return true
	}
	return false
}

func (s *Service) killAll() error {
	sum := ps.Name(s.process)
	err := exception.New()
	for _, p := range sum.Process {
		e := p.Kill()
		if e == nil {
			xEnv.Errorf("pid:%d name:%s kill succeed", p.Pid, p.Name)
			continue
		}

		err.Try(fmt.Sprintf("pid:%d name:%s", p.Pid, p.Name), e)
	}

	return err.Wrap()
}

func query(s string) *reply {
	srv := NewOsquery()
	if e := srv.DetectAndInstall(); e != nil {
		return newReply(nil, e)
	}

	cli, err := osquery.NewClient(ExtensionsSocket, 30*time.Second)
	if err != nil {
		return newReply(nil, err)
	}

	r, err := cli.Query(s)

	return newReply(r, err)
}
