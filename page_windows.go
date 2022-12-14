// +build windows

package hotfix
import "fmt"


func CopyInstruction(location uintptr, data []byte)bool{
	fmt.Println("CopyInstruction")
	return false
}