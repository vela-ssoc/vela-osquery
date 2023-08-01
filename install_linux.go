package osquery

import (
	"fmt"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"os/exec"
	"path/filepath"
)

const (
	ExtensionsSocket = "/dev/osquery.em"
	Package          = "osquery.build.zip"
)

type Service struct {
	process    string
	name       string
	flags      string
	directory  string
	executable string
	pid        string
}

func (s *Service) install(path string) error {
	_, w := auxlib.Stdout()
	defer w.Close()

	cmd := exec.Command("rpm", "-ivh", path)
	cmd.Stdout = w
	cmd.Stderr = w

	defer func() {
		if cmd.Process == nil {
			return
		}

		cmd.Process.Kill()
	}()

	return cmd.Run()
}

func (s *Service) start() error {
	var cmd *exec.Cmd
	if _, e := exec.LookPath("systemctl"); e == nil {
		xEnv.Errorf("osqueryd with systemctl")
		cmd = exec.Command("systemctl", "start", "osqueryd")
	} else {
		xEnv.Errorf("not found systemctl")
	}

	if _, e := exec.LookPath("service"); e == nil {
		xEnv.Errorf("osqueryd with service")
		cmd = exec.Command("service", "osqueryd", "start")
	} else {
		xEnv.Errorf("not found service")
	}

	if cmd == nil {
		return fmt.Errorf("not found system service command")
	}

	_, w := auxlib.Stdout()
	defer w.Close()

	cmd.Stdout = w
	cmd.Stderr = w

	return cmd.Run()
}

func (s *Service) DetectAndInstall() error {
	if s.Ok() {
		return nil
	}

	return s.startup()
}

func (s *Service) build(path string) error {
	_, w := auxlib.Stdout()
	defer w.Close()

	cmd := exec.Command("sh", filepath.Join(path, "build.sh"), path)
	cmd.Stdout = w
	cmd.Stderr = w

	return cmd.Run()
}

func (s *Service) startup() error {
	th, err := xEnv.Third(Package)
	if err != nil {
		return err
	}
	return s.build(th.File())
}

func NewOsquery() *Service {
	return &Service{
		name:    "osqueryd",
		process: "osqueryd",
		pid:     "/run/osqueryd.pidfile",
		flags:   "/etc/osquery/osquery.flags",
	}
}

func startup() error {
	s := NewOsquery()
	return s.startup()
}
