//go:build ignore

// gen_rsrc writes rsrc_windows_{amd64,arm64}.syso: a COFF object with one
// resource, the tray's application manifest, which the Go linker puts into
// the .exe. The manifest makes the tray per-monitor DPI aware (sharp menu,
// icon and window at 150 % and 200 %) and asks for Common Controls 6 (the
// buttons, edit fields and message boxes of current Windows instead of
// Windows 95's). Run `go generate ./cmd/boundgate-tray` after changing it;
// the .syso files are committed, so builds need nothing but Go.
package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
)

const manifest = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="BoundGate.Tray" version="1.0.0.0"/>
  <description>BoundGate</description>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0"
        processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>
`

func main() {
	for _, a := range []struct {
		name    string
		machine uint16
		reloc   uint16 // IMAGE_REL_*_ADDR32NB: an RVA, filled in by the linker
	}{
		{"amd64", 0x8664, 0x0003},
		{"arm64", 0xaa64, 0x0002},
	} {
		if err := os.WriteFile("rsrc_windows_"+a.name+".syso", object(a.machine, a.reloc, []byte(manifest)), 0o644); err != nil {
			log.Fatal(err)
		}
	}
}

// object: file header, one .rsrc section, one relocation, one symbol.
// The section holds a resource tree of three levels (type 24 = manifest,
// ID 1 = the process's own manifest, language neutral), one data entry and
// the data.
func object(machine, reloc uint16, data []byte) []byte {
	const (
		fileHeader = 20
		sectHeader = 40
		dirSize    = 16 + 8 // a directory with one entry
		dataEntry  = 16
		subdir     = 0x80000000
	)
	entryAt := uint32(3 * dirSize)
	dataAt := entryAt + dataEntry
	var sect bytes.Buffer
	w := func(b *bytes.Buffer, v ...any) {
		for _, x := range v {
			_ = binary.Write(b, binary.LittleEndian, x)
		}
	}
	dir := func(id, target uint32) {
		w(&sect, uint32(0), uint32(0), uint16(0), uint16(0), uint16(0), uint16(1)) // one ID entry
		w(&sect, id, target)
	}
	dir(24, subdir|dirSize)                                   // RT_MANIFEST
	dir(1, subdir|2*dirSize)                                  // CREATEPROCESS_MANIFEST_RESOURCE_ID
	dir(0, entryAt)                                           // LANG_NEUTRAL
	w(&sect, dataAt, uint32(len(data)), uint32(0), uint32(0)) // the relocation adds the section's RVA
	sect.Write(data)
	for sect.Len()%8 != 0 {
		sect.WriteByte(0)
	}

	raw := uint32(fileHeader + sectHeader)
	relocs := raw + uint32(sect.Len())
	symbols := relocs + 10
	var f bytes.Buffer
	w(&f, machine, uint16(1), uint32(0), symbols, uint32(1), uint16(0), uint16(0))
	f.WriteString(".rsrc\x00\x00\x00")
	w(&f, uint32(0), uint32(0), uint32(sect.Len()), raw, relocs, uint32(0), uint16(1), uint16(0),
		uint32(0x40000040)) // initialized data, readable
	f.Write(sect.Bytes())
	w(&f, entryAt, uint32(0), reloc) // the data entry's OffsetToData, symbol 0
	f.WriteString(".rsrc\x00\x00\x00")
	w(&f, uint32(0), int16(1), uint16(0), uint8(3), uint8(0)) // section symbol, static
	w(&f, uint32(4))                                          // empty string table
	return f.Bytes()
}
