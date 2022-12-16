package hotfix

import (
	"fmt"
	"reflect"

)

type ProbeFunc struct {
	Point uintptr
	Name string
	Any  interface{}
    Bind string
}

var (
	PROBE_MAP = map[string]*ProbeFunc{}
)
func Probe(x int)string{
    msg := "PROBE:" + fmt.Sprintf("%v", x) + fmt.Sprintf(":%v", x + 1)
    return msg
}

func Probe1() {
    Probe(1)
    Probe(1)
    Probe(1)
    Probe(1)
    Probe(1)
    Probe(1)
    Probe(1)
    Probe(1)
    Probe(1)

}
func Probe2() {
    Probe(2)
    Probe(2)
    Probe(2)
    Probe(2)
    Probe(2)
    Probe(2)
    Probe(2)
    Probe(2)
    Probe(2)
}

func Probe3() {
    Probe(3)
    Probe(3)
    Probe(3)
    Probe(3)
    Probe(3)
    Probe(3)
    Probe(3)
    Probe(3)
    Probe(3)
}
func Probe4() {
    Probe(4)
    Probe(4)
    Probe(4)
    Probe(4)
    Probe(4)
    Probe(4)
    Probe(4)
    Probe(4)
    Probe(4)
}
func Probe5() {
    Probe(5)
    Probe(5)
    Probe(5)
    Probe(5)
    Probe(5)
    Probe(5)
    Probe(5)
    Probe(5)
    Probe(5)
}
func Probe6() {
    Probe(6)
    Probe(6)
    Probe(6)
    Probe(6)
    Probe(6)
    Probe(6)
    Probe(6)
    Probe(6)
    Probe(6)
}
func Probe7() {
    Probe(7)
    Probe(7)
    Probe(7)
    Probe(7)
    Probe(7)
    Probe(7)
    Probe(7)
    Probe(7)
    Probe(7)
}
func Probe8() {
    Probe(8)
    Probe(8)
    Probe(8)
    Probe(8)
    Probe(8)
    Probe(8)
    Probe(8)
    Probe(8)
    Probe(8)
}
func Probe9() {
    Probe(9)
    Probe(9)
    Probe(9)
    Probe(9)
    Probe(9)
    Probe(9)
    Probe(9)
    Probe(9)
    Probe(9)
}
func CretaProbe(in interface{}) *ProbeFunc {
	p := reflect.ValueOf(in).Pointer()
	probe := &ProbeFunc{
		Point: p,
		Any:  in,
	}
	return probe
}

func init() {
    Probe1()
    Probe2()
    Probe3()
    Probe4()
    Probe5()
    Probe9()
    Probe6()
    Probe7()
    Probe8()
    Probe9()
    RegisterProbe(1, Probe1)
    RegisterProbe(2, Probe2)
    RegisterProbe(3, Probe3)
    RegisterProbe(4, Probe4)
    RegisterProbe(5, Probe5)
    RegisterProbe(6, Probe6)
    RegisterProbe(7, Probe7)
    RegisterProbe(8, Probe8)
    RegisterProbe(9, Probe9)

}
func RegisterProbe(id int, in interface{}){
    name := fmt.Sprintf("Probe%v", id)
    PROBE_MAP[name] = CretaProbe(in)
    PROBE_MAP[name].Name = name
}

func GetProbe(name string)*ProbeFunc{
    key := name
    v, ok := PROBE_MAP[key]
    if !ok{
        return nil
    }
    return v
}

func GetFreeProbe()*ProbeFunc{
    for _, v := range PROBE_MAP{
        if len(v.Bind) == 0{
            return v
        }
    }
    return nil
}