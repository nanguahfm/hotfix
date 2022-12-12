// +build windows

package hotfix

func setPageWritable(addr uintptr, length int, prot int) {

}

func CopyInstruction(location uintptr, data []byte)bool{
	return true
}