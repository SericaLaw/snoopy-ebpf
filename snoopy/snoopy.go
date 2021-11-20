package snoopy
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
	"os"
	"os/signal"
	"strings"
	"time"
	"unsafe"
)

const (
	ConfigMaxArg uint32 = iota
	ConfigMaxEnv
)

const (
	DataArg	uint32 = iota
	DataEnv
	DataRet
)

type context struct {
	Ts		uint64
	Type 	uint32
	Pid 	uint32
	Tid 	uint32
	Uid 	uint32
	Ret 	int64
	Comm 	[16]byte
}

type probe struct {
	TracePoint	string
	ProgName 	string
}

type Event struct {
	Ts		uint64
	Pid 	uint32
	Tid 	uint32
	Uid 	uint32
	Ret 	int64
	Comm 	string
	Args	[]string
	Envs	[]string
}


type FormatFunc func(event *Event, printEnv bool) string

func New(config Config) (*Snoopy, error) {
	if config.MaxArg < 0 || config.MaxEnv < 0 {
		return nil, fmt.Errorf("max-args and max-envs should be at least 0")
	}

	if config.MaxArg > 128 || config.MaxEnv > 128 {
		return nil, fmt.Errorf("max-args and max-envs should be at most 128")
	}

	s := &Snoopy{
		config: config,
	}

	if config.MaxEnv > 0 {
		s.printEnv = true
	}

	if config.Formatter == nil {
		s.config.Formatter = defaultFormatter
	}

	var err error
	if s.bpfModule, err = bpf.NewModuleFromFile("snoopy.bpf.o"); err != nil {
		return nil, err
	}

	if err = s.bpfModule.BPFLoadObject(); err != nil {
		return nil, err
	}

	s.configMap, err = s.bpfModule.GetMap("config_map") // u32, u32
	if err != nil {
		return nil, err
	}

	// populate configs
	configMaxArg := uint32(ConfigMaxArg)
	maxArg := uint32(s.config.MaxArg)
	configMaxEnv := uint32(ConfigMaxEnv)
	maxEnv := uint32(s.config.MaxEnv)
	if err = s.configMap.Update(unsafe.Pointer(&configMaxArg), unsafe.Pointer(&maxArg)); err != nil {
		return nil, err
	}
	if err = s.configMap.Update(unsafe.Pointer(&configMaxEnv), unsafe.Pointer(&maxEnv)); err != nil {
		return nil, err
	}

	// attach tracepoints
	probes := []probe{
		{"syscalls:sys_enter_execve", "tracepoint__sys_enter_execve"},
		{"syscalls:sys_exit_execve", "tracepoint__sys_exit_execve"},
		{"syscalls:sys_enter_execveat", "tracepoint__sys_enter_execveat"},
		{"syscalls:sys_exit_execveat", "tracepoint__sys_exit_execveat"},
	}

	for _, p := range probes {
		var prog *bpf.BPFProg
		if prog, err = s.bpfModule.GetProgram(p.ProgName); err != nil {
			return nil, err
		}
		if _, err = prog.AttachTracepoint(p.TracePoint); err != nil {
			return nil, err
		}
	}
	s.lostExecveChan = make(chan uint64)
	s.execveDataChan = make(chan []byte, 300)
	s.execvePerfMap, err = s.bpfModule.InitPerfBuf("execve_out", s.execveDataChan, s.lostExecveChan, 1024)
	if err != nil {
		return nil, err
	}

	s.lostExecveatChan = make(chan uint64)
	s.execveatDataChan = make(chan []byte, 300)
	s.execveatPerfMap, err = s.bpfModule.InitPerfBuf("execveat_out", s.execveatDataChan, s.lostExecveatChan, 1024)
	if err != nil {
		return nil, err
	}

	return s, nil
}

type Snoopy struct {
	bpfModule 	*bpf.Module
	configMap 	*bpf.BPFMap
	config		Config
	printEnv	bool

	execveDataChan	chan []byte
	lostExecveChan	chan uint64
	execvePerfMap	*bpf.PerfBuffer

	execveatDataChan	chan[]byte
	lostExecveatChan	chan uint64
	execveatPerfMap		*bpf.PerfBuffer

	eventsChanOut	chan *Event
}

type Config struct {
	MaxArg	int
	MaxEnv	int
	Formatter 	FormatFunc
}

func (s *Snoopy) Run() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	s.execvePerfMap.Start()
	s.execveatPerfMap.Start()
	done := make(chan struct{})

	s.eventsChanOut = make(chan *Event, 128)

	go s.handler(s.execveDataChan, done)
	go s.handler(s.execveatDataChan, done)

	go s.printer(done)

	<-sig
	close(done)
	s.execvePerfMap.Stop()
	s.execveatPerfMap.Stop()
	s.bpfModule.Close()
}

func (s *Snoopy) handler(input <-chan []byte, done <-chan struct{}) {
	events := make(map[uint32]*Event)
	for rawData := range input {
		dataBuff := bytes.NewBuffer(rawData)
		var ctx context
		err := binary.Read(dataBuff, binary.LittleEndian, &ctx)
		if err != nil {
			panic(err)
		}
		switch ctx.Type {
		case DataArg:
			if _, ok := events[ctx.Tid]; !ok {
				events[ctx.Tid] = &Event{
					Ts:   ctx.Ts,
					Pid:  ctx.Pid,
					Tid:  ctx.Tid,
					Uid:  ctx.Uid,
					Comm: string(ctx.Comm[:]),
					Args: []string{dataBuff.String()},
				}
			} else {
				events[ctx.Tid].Args = append(events[ctx.Tid].Args, dataBuff.String())
			}
		case DataEnv:
			if _, ok := events[ctx.Tid]; ok {
				events[ctx.Tid].Envs = append(events[ctx.Tid].Envs, dataBuff.String())
			}
		case DataRet:
			if _, ok := events[ctx.Tid]; ok {
				events[ctx.Tid].Ret = ctx.Ret
				s.eventsChanOut <- events[ctx.Tid]
				delete(events, ctx.Tid)
			}
		}

		select {
		case <-done:
			return
		default:
			break
		}
	}
}

func (s *Snoopy) printer(done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case event := <-s.eventsChanOut:
			fmt.Printf("%v\n", s.config.Formatter(event, s.printEnv))
		default:
			break
		}
	}
}

func defaultFormatter(event *Event, printEnv bool) string {
	ut := time.Unix(0, int64(event.Ts))
	ut = ut.UTC()
	timestamp := fmt.Sprintf("%02d:%02d:%02d:%06d", ut.Hour(), ut.Minute(), ut.Second(), ut.Nanosecond()/1000)
	if printEnv {
		return fmt.Sprintf("%-16s [uid:%d tid:%d, comm:%s]: %s\n{%s}\n", timestamp, event.Uid, event.Tid, event.Comm, strings.Join(event.Args, " "), strings.Join(event.Envs, " "))
	} else {
		return fmt.Sprintf("%-16s [uid:%d tid:%d, comm:%s]: %s\n", timestamp, event.Uid, event.Tid, event.Comm, strings.Join(event.Args, " "))
	}
}
