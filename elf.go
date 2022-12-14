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
	"time"
	"unsafe"

	"strings"

	"github.com/agiledragon/gomonkey"
	"github.com/go-delve/delve/pkg/proc"
	"go.uber.org/zap"

)

const (
	HOTFIX_FAIL = "HOTFIX_FAIL"
	HOTFIX_OK   = "HOTFIX_OK"


	HOT_MONKRY = 1
	HOT_HFMKRY = 2
	HOT_TRACE = 3
)

var (
	HOTFIX_PACKET = "gamefix"
	TRACER_PATH   = "./tracer"
	HOTFIX_PREFIX = "HF_"
)
type  HotFuncData struct{
	From map[string]reflect.Value
	To map[string]reflect.Value
	BackUP2 map[string][]byte
	Entrys map[string]*proc.Function
	NewUP2 map[string][]byte
	ProbeCode map[string][]byte
	ProbeFunc map[string]string
	BackUP1 map[string][]byte
	NewUP1 map[string][]byte
	Patch map[string]int

	ADDR map[string]string

}

var(
	HOTFIX_MAP = map[string]map[string]string{}
	PATCH_MAP = map[string]*gomonkey.Patches{}
	HOTFIX_LOAD_PACKETS = map[string]string{}


	HOTFIX_FUNC_DATA =  map[string]*HotFuncData{}
	HOT_MIN_CODE_SIZE= 0
)
var(
	BK_Instruction = []byte{}
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
func Hotfix(logger *zap.Logger, path string, names []string, variadic []bool, safe int) (string, error) {
	logger = logger.With(zap.Namespace("hotfix"))
	pathso := path
	if !strings.HasSuffix(pathso, ".so"){
		pathso += ".so"
	}

	if safe <= 0{
		s, e := hotfix1(logger, pathso, names, variadic)	
		return s, e
	}
	for _, elem := range names{
		ResetPatch(logger, elem, pathso)
	}
	s, e := hotfix2(logger, pathso, names, safe)
	if e != nil{
		return s, e
	}
	HOTFIX_MAP[path] = make(map[string]string)
	for _, name := range names{
		hot, _ := GetHotName(name)
		HOTFIX_MAP[path][name] = hot + fmt.Sprintf("@%v",safe)
	}
	HOTFIX_LOAD_PACKETS[HOTFIX_PACKET] = time.Now().UTC().String()
	return s, e
}

func hotfix1(logger *zap.Logger, path string, names []string, variadic []bool) (string, error) {
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
	for i := 1; i<= 10; i += 1{
		key := fmt.Sprintf("server/server.Probe%v", i)
		entry, err := dwarf.FindFuncEntry(key)
		if err == nil{
			logger.Warn("dwarf.FindFuncEntry", zap.Any(key, fmt.Sprintf("%X", entry.Entry)) )
		}
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
	BK_Instruction = dwarf.BI().Arch.BreakpointInstruction()
	for i, name := range names{
		_, ok := HOTFIX_FUNC_DATA[path]
		if !ok{
			HOTFIX_FUNC_DATA[path] = &HotFuncData{
				From:   map[string]reflect.Value{},
				To:     map[string]reflect.Value{},
				BackUP2: map[string][]byte{},
				Entrys: map[string]*proc.Function{},
				NewUP2:  map[string][]byte{},
				
				BackUP1: map[string][]byte{},
				NewUP1:  map[string][]byte{},
				Patch: map[string]int{},
				ADDR: map[string]string{},
				ProbeCode : map[string][]byte{},
				ProbeFunc : map[string]string{},
			}
		}
		v := HOTFIX_FUNC_DATA[path]
		from := oldFunctions[i]
		to := newFunctions[i]
		v.From[name] = from
		hotName, _ := GetHotName(name)
		v.To[hotName] = to
		{
			probe := GetFreeProbe()
			if probe != nil{
				code := buildJmpRelative(from.Pointer(), probe.Point, HOT_MIN_CODE_SIZE)
				logger.Warn(name,  zap.Any("size", from.Pointer() -  probe.Point),  zap.Any("code", len(code)) )
				bak := BackInstruction(from.Pointer(), code)
				v.BackUP2[name] = bak
				v.NewUP2[name] = code

				code1 := buildJmpDirective(to.Pointer())
				codex := []byte{0x90,0x90}
				codex = append(codex, code1...)
				codex = append(codex, []byte{0x90,0x90,0x90,0x90,0x90,0x90}...)
				v.ProbeCode[name] = codex
				v.ProbeFunc[name] = probe.Name
				v.NewUP2[probe.Name] = codex
				v.ADDR[probe.Name] = fmt.Sprintf("%X", probe.Point)
			}


		}
		{
			code := buildJmpDirective(to.Pointer())
			bak := BackInstruction(from.Pointer(), code)
			v.BackUP1[name] = bak
			v.NewUP1[name] = code
		}

		v.ADDR[hotName] = fmt.Sprintf("%X", to.Pointer())
		v.ADDR[name] = fmt.Sprintf("%X", from.Pointer())
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

func hotfix2(logger *zap.Logger, path string, names []string, safe int)(string, error){
	v, ok := HOTFIX_FUNC_DATA[path]
	if !ok{
		logger.Warn("hotfix2", zap.Any(path, safe))
		return "hotfixsofalil", fmt.Errorf("hotfixsofalil")
	}
	oldFunctions := []reflect.Value{}
	newFunctions := []reflect.Value{}
	oldFunctionEntrys := []*proc.Function{}
	for _, elem := range names{
		from, ok1 := v.From[elem]
		hotName, _ := GetHotName(elem)
		to, ok2 := v.To[hotName]
		entry, ok3 := v.Entrys[elem]
		if !ok1 || !ok2 || ok3{
			logger.Error("hotfix2", zap.Any("elem", hotName) )
			return "hotfixfuncfalil", fmt.Errorf("hotfixfuncfalil %v", elem)
		}
		oldFunctions = append(oldFunctions, from)
		newFunctions = append(newFunctions, to)
		oldFunctionEntrys = append(oldFunctionEntrys, entry)
	}
	for i, elem := range names{
		logger.Warn("hotfix2", zap.Any("elem", elem), zap.Any(fmt.Sprintf("%X", oldFunctions[i].Pointer()),fmt.Sprintf("%X", newFunctions[i].Pointer())) )
	}

	if safe == HOT_MONKRY {
		monkeyPatch(oldFunctions, newFunctions, names)
	}
	if safe == HOT_HFMKRY{
		for _, name := range names{
			from := v.From[name]
			code := v.NewUP2[name]
			logger.Warn("HOT_HFMKRY", zap.Any("name", name), zap.Any(fmt.Sprintf("%X", from.Pointer()), len(code)) )
			if len(code) <= 0{
				return "hotfixfunc", fmt.Errorf("hotfixfunc %v", name)
			}
			{
				code1 := v.ProbeCode[name]
				p := GetProbe(v.ProbeFunc[name])
				if p == nil || len(code1) == 0{
					return "hotfixfunc0", fmt.Errorf("hotfixfunc0 %v %v", name, len(code1))
				}
				ok := CopyInstruction(p.Point, code1)
				if !ok{
					return "hotfixfunc1", fmt.Errorf("hotfixfunc1 %v", name)
				}
				p.Bind = name
			}
			ok := CopyInstruction(from.Pointer(), code)
			if !ok{
				return "hotfixfunc2", fmt.Errorf("hotfixfunc2 %v", name)
			}

		}
	}
	if safe == HOT_TRACE{

		ret, err := patch(path, names,  oldFunctionEntrys, newFunctions)
		if err != nil{
			logger.Warn("hotfix2", zap.Any("ret", ret), zap.Error(err) )
			return ret, err
		}
	}
	for _, name := range names{
		v.Patch[name] = safe
	}
	return "OK", nil
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





func BackInstruction(location uintptr, data []byte)[]byte{
	bytes := entryAddress(location, len(data))
	original := make([]byte, len(bytes))
	copy(original, bytes)
	return original
}



func buildJmpRelative(from, to uintptr, minJmpCodeSize int) []byte{
	var code []byte
	delta := int64(from - to)
	if unsafe.Sizeof(uintptr(0)) == unsafe.Sizeof(int32(0)) {
		delta = int64(int32(from - to))
	}
	
	relative := (delta <= 0x7fffffff)
	if delta < 0 {
		delta = -delta
		relative = (delta <= 0x80000000)
	}
	
	
	if relative {
		var dis uint32
		if to > from {
			dis = uint32(int32(to-from) - 5)
		} else {
			dis = uint32(-int32(from-to) - 5)
		}
		code = []byte{
			0xe9,
				byte(dis),
				byte(dis >> 8),
				byte(dis >> 16),
				byte(dis >> 24),
		}
	}else{
		return code
	}
	sz := len(code)
	if minJmpCodeSize > 0 && sz < minJmpCodeSize {
		nop := make([]byte, 0, minJmpCodeSize-sz)
		for {
			if len(nop) >= minJmpCodeSize-sz {
				break
			}
			nop = append(nop, 0x90)
		}
		code = append(code, nop...)
	}
	return code
}



func patch(path string, names []string,  oldFunctions []*proc.Function, newFunctions []reflect.Value) (string, error) {
	param := TracerParam{
		Pid:                   os.Getpid(),
		Path:                  path,
		Names:                 names,
		BreakpointInstruction: BK_Instruction,
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

func ResetPatch(logger *zap.Logger, patch string, so string){
	v, ok := PATCH_MAP[patch]
	if ok{
		logger.Warn("ResetPatch", zap.Any("", patch))
		v.Reset()
		delete(PATCH_MAP, patch)
		for k, _ := range HOTFIX_MAP{
			_, ok := HOTFIX_MAP[k][patch]
			if ok{
				delete(HOTFIX_MAP[k], patch)
			}
		}
	}
	{
		v, ok := HOTFIX_FUNC_DATA[so]
		if ok{
			name := patch
			hot := v.Patch[patch]
			if hot != HOT_HFMKRY{
				return
			}
			from := v.From[name]
			code := v.BackUP2[name]
			ok1 := CopyInstruction(from.Pointer(), code)
			if ok1{
				v.Patch[name] = 0
			}
		}

	}
}

//go:linkname buildJmpDirective github.com/agiledragon/gomonkey.buildJmpDirective
func buildJmpDirective(double uintptr) []byte

//go:linkname getPointer github.com/agiledragon/gomonkey.getPointer
func getPointer(v reflect.Value) unsafe.Pointer
