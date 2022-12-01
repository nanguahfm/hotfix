package hotfix

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"plugin"
	"reflect"
	"sync"
	"unsafe"

	"strings"

	

	"github.com/agiledragon/gomonkey"
	"github.com/go-delve/delve/pkg/proc"
	"go.uber.org/zap"
)

const (
	HOTFIX_FAIL = "HOTFIX_FAIL"
	HOTFIX_OK   = "HOTFIX_OK"
)

var (
	HOTFIX_PACKET = "gamefix"
	TRACER_PATH   = "./tracer"
	HOTFIX_PREFIX = "HF_"
)

var(
	HOTFIX_MAP = map[string]map[string]string{}
	PATCH_MAP = map[string]*gomonkey.Patches{}
	HOTFIX_CURR_PACKET = "gamefix"
)

var(
	SO_COMMIT = "000000"
)

func GetHotName(name string) (string, string) {
	if strings.Contains(name, "(*"){
		name = strings.Replace(name, "(*", "(*HF_", 1)
	}else{
		name = strings.Replace(name, "(", "(HF_", 1)
	}
	vec := strings.Split(name, "/")
	raw := vec[1]
	{
		ns := strings.Split(vec[1], ".")
		ns[0] = HOTFIX_PACKET
		size := len(ns)
		raw = ns[size -1]
		ns[size -1] = HOTFIX_PREFIX + raw
		vec[1] = strings.Join(ns, ".")
	}
	hotName := strings.Join(vec, "/")
	return hotName, raw
}
func Hotfix(logger *zap.Logger, path string, names []string, variadic []bool, safe bool) (string, error) {
	logger = logger.With(zap.Namespace("hotfix"))
	pathso := path
	if !strings.HasSuffix(pathso, ".so"){
		pathso += ".so"
	}
	for _, elem := range names{
		ResetPatch(logger, elem)
	}
	s, e := hotfix(logger, pathso, names, variadic, safe)
	if e == nil{
		HOTFIX_MAP[path] = make(map[string]string)
		for _, name := range names{
			hot, _ := GetHotName(name)
			HOTFIX_MAP[path][name] = hot
		}
		HOTFIX_CURR_PACKET = HOTFIX_PACKET
	}
	return s, e
}

func hotfix(logger *zap.Logger, path string, names []string, variadic []bool, safe bool) (string, error) {
	dwarf, err := NewDwarfRT("")
	logger.Warn("hotfix_DwarfRT1")
	if err != nil {
		return HOTFIX_FAIL, err
	}

	isVariadic := func(i int) bool {
		if i >= len(variadic) {
			return false
		}
		return variadic[i]
	}
	oldFunctionEntrys := make([]*proc.Function, 0, len(names))
	for _, name := range names {
		entry, err := dwarf.FindFuncEntry(name)
		if err != nil {
			return HOTFIX_FAIL, fmt.Errorf("not found function: %s in main  err:%s", name, err)
		}
		oldFunctionEntrys = append(oldFunctionEntrys, entry)
	}
	logger.Warn("hotfix_DwarfRT2")
	p, err := plugin.Open(path)
	if err != nil {
		return HOTFIX_FAIL, err
	}
	logger.Warn("hotfix_DwarfRT3")
	lib, addr, err := dwarf.SearchPluginByName(path)
	logger.Warn("hotfix_DwarfRT4")
	if err != nil {
		return HOTFIX_FAIL, err
	}
	if lib == "" {
		return HOTFIX_FAIL, fmt.Errorf("not found lib: %s in main  err:%s", path, err)
	}
	err = dwarf.AddImage(lib, addr)
	logger.Warn("hotfix_DwarfRT5")
	if err != nil {
		return HOTFIX_FAIL, err
	}

	hotfixFunctionType, hotfixFunctionTypeErr := p.Lookup("HotfixFunctionType")
	getHotfixFunction := func(name string) (reflect.Value, bool) {
		if hotfixFunctionTypeErr != nil {
			return reflect.Value{}, false
		}
		hotfixTypeFn, ok := hotfixFunctionType.(func(string) reflect.Type)
		if !ok {
			return reflect.Value{}, false
		}
		typ := hotfixTypeFn(name)
		if typ == nil {
			return reflect.Value{}, false
		}
		hotname, raw := GetHotName(name)
		dwarf.ForeachFunc(func(namex string, pc uint64) {
			if strings.Contains(namex, raw) {
				logger.Warn("ForeachFunc", zap.Any(namex, raw) )
			}
		})
		pc, err := dwarf.FindFuncPc(hotname)
		logger.Warn("dwarf.FindFuncPc", zap.Any(hotname, pc))
		if err != nil || pc == 0 {
			return reflect.Value{}, false
		}

		f := reflect.MakeFunc(typ, nil)
		funcPtrVal := reflect.ValueOf(f).FieldByName("ptr").Pointer()
		funcPtr := (*Func)(unsafe.Pointer(funcPtrVal))
		funcPtr.codePtr = uintptr(pc)
		return f, true
	}

	newFunctions := make([]reflect.Value, 0, len(names))
	oldFunctions := make([]reflect.Value, 0, len(names))
	for i, name := range names {
		logger.Warn("getHotfixFunction", zap.Any(name, i))
		f, ok := getHotfixFunction(name)
		if !ok {
			hotName, _ := GetHotName(name)
			logger.Warn("start dwarf.FindFunc ", zap.Any(hotName, i))
			f, err = dwarf.FindFunc(hotName, isVariadic(i))
			if err != nil {
				return HOTFIX_FAIL, fmt.Errorf("dwarf.FindFunc not found %s in plugin err:%#v", hotName, err)
			}
		}
		if uint64(f.Pointer()) == oldFunctionEntrys[i].Entry {
			return HOTFIX_FAIL, fmt.Errorf("function %s equl %v in plugin err:%#v", name, f.Pointer(), err)
		}
		newFunctions = append(newFunctions, f)
		oldFunc := reflect.MakeFunc(f.Type(), nil)
		funcPtrVal := reflect.ValueOf(oldFunc).FieldByName("ptr").Pointer()
		funcPtr := (*Func)(unsafe.Pointer(funcPtrVal))
		funcPtr.codePtr = uintptr(oldFunctionEntrys[i].Entry)
		oldFunctions = append(oldFunctions, oldFunc)
	}

	for i := 0; i < len(oldFunctionEntrys); i++ {
		jumpCode := buildJmpDirective(0)
		if (oldFunctionEntrys[i].End - oldFunctionEntrys[i].Entry) < uint64(len(jumpCode)) {
			logger.Warn("jump_size",  zap.Any("size", len(jumpCode)  ) )
			return HOTFIX_FAIL, fmt.Errorf("jump_code error %s", names[i])
		}
	}

	if !safe {
		for i, elem := range names{
			logger.Warn("monkeyPatch ", zap.Any("elem", elem), zap.Any(fmt.Sprintf("%X", oldFunctions[i].Pointer()),fmt.Sprintf("%X", newFunctions[i].Pointer())) )
		}
		monkeyPatch(oldFunctions, newFunctions, names)
		
	}else{
		ret, err := patch(path, names, dwarf.BI(), oldFunctionEntrys, newFunctions)
		if err != nil{
			return ret, err
		}
	}
	{
		GetSoCommitId, err := p.Lookup("GetSoCommitId")
		if err == nil {
			GetSoCommitIdFn, ok := GetSoCommitId.(func() string)
			if ok {
				SO_COMMIT = GetSoCommitIdFn()
			}
		}

	}
	return HOTFIX_OK, nil
	
}

type TracerParam struct {
	Pid                   int
	Path                  string
	Names                 []string
	FunctionEntry         []uint64
	JumpCode              [][]byte
	BreakpointInstruction []byte
}

var patchFuncMutex sync.Mutex
var patchFuncs []reflect.Value

func patch(path string, names []string, bi *proc.BinaryInfo, oldFunctions []*proc.Function, newFunctions []reflect.Value) (string, error) {
	param := TracerParam{
		Pid:                   os.Getpid(),
		Path:                  path,
		Names:                 names,
		BreakpointInstruction: bi.Arch.BreakpointInstruction(),
	}

	for i := 0; i < len(oldFunctions); i++ {
		newFunc := newFunctions[i]
		patchFuncMutex.Lock()
		patchFuncs = append(patchFuncs, newFunc)
		patchFuncMutex.Unlock()

		param.FunctionEntry = append(param.FunctionEntry, oldFunctions[i].Entry)
		param.JumpCode = append(param.JumpCode, buildJmpDirective((uintptr)(getPointer(newFunc))))
	}

	paramBuf, err := json.Marshal(param)
	if err != nil {
		return HOTFIX_FAIL, err
	}

	paramStr := base64.StdEncoding.EncodeToString(paramBuf)

	cmd := exec.Command(TRACER_PATH, paramStr)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err = cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return HOTFIX_FAIL, fmt.Errorf("%d %s", exitError.ExitCode(), output.String())
		}
		return HOTFIX_FAIL, fmt.Errorf("%v %s", err, output.String())
	}
	// fmt.Println(output.String())
	return output.String(), nil
}

func monkeyPatch(oldFunctions []reflect.Value, newFunctions []reflect.Value, names []string) {
	for i := 0; i < len(oldFunctions); i++ {
		patch := gomonkey.ApplyFunc(oldFunctions[i].Interface(), newFunctions[i].Interface())
		PATCH_MAP[names[i]] = patch
	}
}

func ResetPatch(logger *zap.Logger, patch string){
	v, ok := PATCH_MAP[patch]
	if ok{
		logger.Warn("ResetPatch", zap.Any("", patch))
		v.Reset()
	}
}

//go:linkname buildJmpDirective github.com/agiledragon/gomonkey.buildJmpDirective
func buildJmpDirective(double uintptr) []byte

//go:linkname getPointer github.com/agiledragon/gomonkey.getPointer
func getPointer(v reflect.Value) unsafe.Pointer
