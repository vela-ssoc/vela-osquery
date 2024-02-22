package osquery

import (
	"fmt"
	"github.com/vela-ssoc/vela-kit/fileutil"
	"github.com/vela-ssoc/vela-kit/stdutil"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const ExtensionsSocket = "\\\\.\\pipe\\osquery.em"

type Service struct {
	svc        *mgr.Service
	name       string
	pid        string
	process    string
	directory  string
	executable string
}

type ServiceInfo struct {
	last    svc.Status
	current svc.Status
}

func (s *Service) open() error {
	if s.svc != nil {
		return nil
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	sv, err := m.OpenService(s.name)

	switch {
	case err == nil:
		s.svc = sv
		return nil
	case err == windows.ERROR_SERVICE_DOES_NOT_EXIST:
		return nil
	default:
		return err
	}
}

func (s *Service) modify() bool {
	return true
}

func (s *Service) have() (bool, error) {
	fi, err := os.Stat(s.directory)
	if err != nil {
		return false, err
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("osquery file changes not directory")
	}

	fi, err = os.Stat(s.executable)
	if err != nil {
		return false, err
	}

	info, err := xEnv.Third("osquery.window.zip")
	if err != nil {
		return false, err
	}

	if info.Changed {
		return false, fmt.Errorf("osquery chanaged must update")
	}

	h1, err := fileutil.Md5(s.executable)
	if err != nil {
		return false, err
	}

	h2, err := fileutil.Md5(filepath.Join(info.File(), "osqueryd", "osqueryd.exe"))
	if err != nil {
		return false, err
	}

	if h1 != h2 {
		return false, fmt.Errorf("osquery file found change")
	}

	return true, nil
}

func (s *Service) control(to svc.Cmd, state svc.State, info *ServiceInfo) error {
	if s.svc == nil {
		return nil
	}

	status, err := s.svc.Query()
	if err != nil {
		return err
	}

	if status.State&state == status.State {
		return nil
	}

	info.last = status
	current, err := s.svc.Control(to)
	info.current = current
	return err
}

func (s *Service) resetAll() error {
	var info ServiceInfo
	var err error

	if s.svc == nil {
		goto install
	}

	err = s.control(svc.Stop, svc.Stopped|svc.StopPending, &info)
	if err != nil {
		return err
	}
	xEnv.Errorf("stop osquery service succeed %v", info)

	xEnv.Errorf("delete osquery service succeed %v", info)
install:
	err = s.killAll()
	if err != nil {
		return err
	}

	err = os.RemoveAll(s.directory)
	if err != nil {
		return err
	}

	th, err := xEnv.Third("osquery.window.zip")
	if err != nil {
		return err
	}

	err = fileutil.CopyTree(th.File(), s.directory, fileutil.Default)
	if err != nil {
		return err
	}

	err = s.install()
	return err
}

func (s *Service) install() error {
	console := stdutil.New(stdutil.Console())
	defer func() {
		_ = console.Close()
	}()

	cmd := exec.Command(s.executable, "--install", "--verbose")
	cmd.Stdout = console
	cmd.Stderr = console

	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		_ = console.Close()
	}()

	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func (s *Service) start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	sv, err := m.OpenService(s.name)
	if err != nil {
		return fmt.Errorf("could not access service: %v", err)
	}
	defer sv.Close()

	status, err := sv.Query()
	if err != nil {
		return err
	}

	switch status.State {
	case svc.Running:
		return nil
	case svc.StartPending:
		i := 0
		tk := time.NewTicker(300 * time.Millisecond)
		for range tk.C {
			i++
			if i > 10*10 {
				return fmt.Errorf("osquery service start pending timeout: 30s")
			}
			status, err = sv.Query()
			if err != nil {
				return err
			}

			if status.State == svc.Running {
				return nil
			}
		}
		return fmt.Errorf("osquery service start timeout: 30s")

	default:
		return sv.Start()
	}
}

func (s *Service) startup() error {
	ok, err := s.have()
	if !ok {
		xEnv.Errorf("startup %v", err)
		if e := s.resetAll(); e != nil {
			return e
		}
		xEnv.Errorf(" reset osquery service succeed")
	}

	return s.start()
}

func (s *Service) DetectAndInstall() error {
	if s.Ok() {
		return nil
	}

	err := s.open()
	if err != nil {
		return err
	}

	err = s.start()
	if err == nil && s.Ok() {
		return nil
	}

	return s.startup()
}

func NewOsquery() *Service {
	s := &Service{
		name:       "osqueryd",
		pid:        "C:\\Program Files\\osquery\\osqueryd.pidfile",
		process:    "osqueryd.exe",
		directory:  "C:\\Program Files\\osquery",
		executable: "C:\\Program Files\\osquery\\osqueryd\\osqueryd.exe",
	}

	return s
}

func startup() error {
	s := NewOsquery()

	if err := s.open(); err != nil {
		return err
	}

	defer func() {
		if s.svc != nil {
			s.svc.Close()
		}
	}()

	return s.startup()
}
