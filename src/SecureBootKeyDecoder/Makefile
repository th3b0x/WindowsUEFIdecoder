#
# EDIT
# This file is scavenged from the EDKII build utility
#
#EXAMPLES
#BASE_DIR = C:\projects\WindowsUEFIdecoder
#SOURCE_DIRECTORY = $(BASE_DIR)\src
#MODULE_NAME = SecureBootKeyDecoder
#CPP_TOOLCHAIN_DIR = C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.0.0\bin\Hostx86\x64
#MAKE_TOOLCHAIN_DIR = C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.0.0\bin\Hostx86\x86
#RESOURCE_COMPILER_DIR = C:\Program Files (x86)\Windows Kits\10\bin\10.0.0.0\x86
#ASL_COMPILER_DIR = C:\Program Files\ASL
#ASM_LINK_DIR = C:\WINDDK\0.0\bin\bin16
#ASL_COMPILER_DIR = C:\Program Files\NASM

BASE_DIR = 
SOURCE_DIRECTORY = $(BASE_DIR)\src
MODULE_NAME = SecureBootKeyDecoder
CPP_TOOLCHAIN_DIR = 
MAKE_TOOLCHAIN_DIR = 
RESOURCE_COMPILER_DIR = 
ASL_COMPILER_DIR =
ASM_LINK_DIR = 
NASM_DIR =

#
# Module Macro Definition
#

MODULE_NAME_GUID = $(MODULE_NAME)
MODULE_VERSION = 1.0
MODULE_TYPE = OTHER_APPLICATION
MODULE_FILE = $(MODULE_NAME).inf
MODULE_FILE_BASE_NAME = $(MODULE_NAME)
BASE_NAME = $(MODULE_NAME)
MODULE_DIR = $(SOURCE_DIRECTORY)\$(MODULE_NAME)
FFS_OUTPUT_DIR = 

MODULE_ENTRY_POINT = ShellCEntryLib
ARCH_ENTRY_POINT = ShellCEntryLib
IMAGE_ENTRY_POINT = _ModuleEntryPoint

INF_VERSION = 1.25
BASE_NAME = $(MODULE_NAME)
MODULE_TYPE = OTHER_APPLICATION
VERSION_STRING = 1.0
VALID_ARCHITECTURES = X64

#
# Build Configuration Macro Definition
#
ARCH = X64
TOOLCHAIN = VS2019
TOOLCHAIN_TAG = VS2019
TARGET = RELEASE

#
# Shell Command Macro
#
CP = copy /y
MV = move /y
RM = del /f /q
MD = mkdir
RD = rmdir /s /q

#
# Build Directory Macro Definition
#
WORKSPACE = $(SOURCE_DIRECTORY)\$(MODULE_NAME)
BUILD_DIR = $(BASE_DIR)\build
BIN_DIR = $(BUILD_DIR)\X64
LIB_DIR = $(BIN_DIR)
MODULE_BUILD_DIR = $(BIN_DIR)\$(MODULE_NAME)
OUTPUT_DIR = $(MODULE_BUILD_DIR)\OUTPUT
DEBUG_DIR = $(MODULE_BUILD_DIR)\DEBUG
DEST_DIR_OUTPUT = $(OUTPUT_DIR)
DEST_DIR_DEBUG = $(DEBUG_DIR)




#
# Tools definitions specific to this module
#
ASLPP = $(CPP_TOOLCHAIN_DIR)\cl.exe
ASLPP_FLAGS = /nologo /E /C /FIAutoGen.h /w

PKCS7SIGN = Pkcs7Sign

VPDTOOL = BPDG

ASLDLINK = $(CPP_TOOLCHAIN_DIR)\link.exe
ASLDLINK_FLAGS = /NODEFAULTLIB /ENTRY:ReferenceAcpiTable /SUBSYSTEM:CONSOLE

GENFW = GenFw
GENFW_FLAGS = 


SLINK = $(CPP_TOOLCHAIN_DIR)\lib.exe
SLINK_FLAGS = /NOLOGO /LTCG

OBJCOPY_ADDDEBUGFLAG =  
OBJCOPY = echo
OBJCOPY_FLAGS = objcopy not needed for

DEPS_FLAGS = /showIncludes


ASM_FLAGS = /nologo /c /W3 /Cx /Zd
ASM = $(CPP_TOOLCHAIN_DIR)\ml64.exe

CC_FLAGS = /nologo /c /GS- /W4 /Gs32768 /D UNICODE /O1b2s /GL /Gy /FIAutoGen.h /EHs-c- /GR- /GF /Gw
CC = $(CPP_TOOLCHAIN_DIR)\cl.exe

ASMLINK = $(ASM_LINK_DIR)\link16.exe
ASMLINK_FLAGS = /nologo /tiny

TIANO = TianoCompress

LZMA = LzmaCompress

VFR = VfrCompile
VFR_FLAGS = -l -n

ASLCC = $(CPP_TOOLCHAIN_DIR)\cl.exe
ASLCC_FLAGS = /nologo /c /FIAutoGen.h /w /TC /Dmain=ReferenceAcpiTable

APP = $(CPP_TOOLCHAIN_DIR)\cl.exe
APP_FLAGS = /nologo /E /TC

NASM_FLAGS = -Ox -f win64
NASM = $(NASM_DIR)\nasm


OPTROM = EfiRom
OPTROM_FLAGS = -e

DTC_FLAGS = -H epapr
DTC = dtc

MAKE = $(MAKE_TOOLCHAIN_DIR)\nmake.exe

SYMRENAME = echo
SYMRENAME_FLAGS = Symbol renaming not needed for

ASM16 = $(MAKE_TOOLCHAIN_DIR)\ml.exe

LZMAF86 = LzmaF86Compress

CRC32 = GenCrc32


BROTLI = BrotliCompress

RC = $(RESOURCE_COMPILER_DIR)\rc.exe

PP = $(CPP_TOOLCHAIN_DIR)\cl.exe
PP_FLAGS = /nologo /E /TC /FIAutoGen.h

VFRPP = $(CPP_TOOLCHAIN_DIR)\cl.exe
VFRPP_FLAGS = /nologo /E /TC /DVFRCOMPILE /FI$(MODULE_NAME)StrDefs.h

DLINK_FLAGS = /NOLOGO /NODEFAULTLIB /IGNORE:4001 /IGNORE:4281 /IGNORE:4254 /OPT:REF /OPT:ICF=10 /MAP /ALIGN:32 /SECTION:.xdata,D /SECTION:.pdata,D /Machine:X64 /LTCG /DLL /ENTRY:$(IMAGE_ENTRY_POINT) /SUBSYSTEM:EFI_BOOT_SERVICE_DRIVER /SAFESEH:NO /BASE:0 /DRIVER /MERGE:.rdata=.data
DLINK = $(CPP_TOOLCHAIN_DIR)\link.exe


RSA2048SHA256SIGN = Rsa2048Sha256Sign


ASL = $(ASL_COMPILER_DIR)\iasl.exe
ASL_FLAGS = 
ASL_OUTFLAGS =  -p



NASMB_FLAGS = -f bin

DLINK2_FLAGS = /WHOLEARCHIVE

DTCPP = cpp


MAKE_FILE = $(MODULE_BUILD_DIR)\Makefile

#
# Build Macro
#
OBJECT_FILES =  \
    $(OUTPUT_DIR)\AutoGen.obj \
    $(OUTPUT_DIR)\$(MODULE_NAME).obj \
    $(OUTPUT_DIR)\asn1_ber_decoder.obj \
    $(OUTPUT_DIR)\oid_registry.obj \
    $(OUTPUT_DIR)\x509.obj

STATIC_LIBRARY_FILES =  \
    $(BIN_DIR)\MdeModulePkg\Library\UefiHiiLib\UefiHiiLib\OUTPUT\UefiHiiLib.lib \
    $(BIN_DIR)\MdeModulePkg\Library\UefiHiiServicesLib\UefiHiiServicesLib\OUTPUT\UefiHiiServicesLib.lib \
    $(BIN_DIR)\MdeModulePkg\Library\UefiSortLib\UefiSortLib\OUTPUT\UefiSortLib.lib \
    $(BIN_DIR)\MdePkg\Library\BaseDebugLibNull\BaseDebugLibNull\OUTPUT\BaseDebugLibNull.lib \
    $(BIN_DIR)\MdePkg\Library\BaseLib\BaseLib\OUTPUT\BaseLib.lib \
    $(BIN_DIR)\MdePkg\Library\BaseMemoryLib\BaseMemoryLib\OUTPUT\BaseMemoryLib.lib \
    $(BIN_DIR)\MdePkg\Library\BasePcdLibNull\BasePcdLibNull\OUTPUT\BasePcdLibNull.lib \
    $(BIN_DIR)\MdePkg\Library\BasePrintLib\BasePrintLib\OUTPUT\BasePrintLib.lib \
    $(BIN_DIR)\MdePkg\Library\UefiApplicationEntryPoint\UefiApplicationEntryPoint\OUTPUT\UefiApplicationEntryPoint.lib \
    $(BIN_DIR)\MdePkg\Library\UefiBootServicesTableLib\UefiBootServicesTableLib\OUTPUT\UefiBootServicesTableLib.lib \
    $(BIN_DIR)\MdePkg\Library\UefiDevicePathLib\UefiDevicePathLib\OUTPUT\UefiDevicePathLib.lib \
    $(BIN_DIR)\MdePkg\Library\UefiFileHandleLib\UefiFileHandleLib\OUTPUT\UefiFileHandleLib.lib \
    $(BIN_DIR)\MdePkg\Library\UefiLib\UefiLib\OUTPUT\UefiLib.lib \
    $(BIN_DIR)\MdePkg\Library\UefiMemoryAllocationLib\UefiMemoryAllocationLib\OUTPUT\UefiMemoryAllocationLib.lib \
    $(BIN_DIR)\MdePkg\Library\UefiRuntimeServicesTableLib\UefiRuntimeServicesTableLib\OUTPUT\UefiRuntimeServicesTableLib.lib \
    $(BIN_DIR)\ShellPkg\Library\UefiShellCEntryLib\UefiShellCEntryLib\OUTPUT\UefiShellCEntryLib.lib \
    $(BIN_DIR)\ShellPkg\Library\UefiShellLib\UefiShellLib\OUTPUT\UefiShellLib.lib \
    $(OUTPUT_DIR)\$(MODULE_NAME).lib

INC =  \
    /I$(WORKSPACE) \
    /I$(DEBUG_DIR) \
    /I$(WORKSPACE)\MdePkg \
    /I$(WORKSPACE)\MdePkg\Include \
    /I$(WORKSPACE)\MdePkg\Include\X64 \
    /I$(WORKSPACE)\ShellPkg \
    /I$(WORKSPACE)\ShellPkg\Include

OBJECT_FILES_LIST = $(DEST_DIR_OUTPUT)\object_files.lst
STATIC_LIBRARY_FILES_LIST = $(DEST_DIR_OUTPUT)\static_library_files.lst
OBJLIST_0 = $(OUTPUT_DIR)\oid_registry.obj $(OUTPUT_DIR)\AutoGen.obj $(OUTPUT_DIR)\x509.obj $(OUTPUT_DIR)\asn1_ber_decoder.obj $(OUTPUT_DIR)\$(MODULE_NAME).obj


#
# Overridable Target Macro Definitions
#
FORCE_REBUILD = force_build
INIT_TARGET = init
PCH_TARGET =
BC_TARGET = 
CODA_TARGET = $(DEST_DIR_OUTPUT)\$(MODULE_NAME).exe \
              

#
# Default target, which will build dependent libraries in addition to source files
#

all: mbuild


#
# Target used when called from platform makefile, which will bypass the build of dependent libraries
#

pbuild: $(INIT_TARGET) $(BC_TARGET) $(PCH_TARGET) $(CODA_TARGET)

#
# ModuleTarget
#

mbuild: $(INIT_TARGET) $(BC_TARGET) gen_libs $(PCH_TARGET) $(CODA_TARGET)

#
# Build Target used in multi-thread build mode, which will bypass the init and gen_libs targets
#

tbuild: $(BC_TARGET) $(PCH_TARGET) $(CODA_TARGET)

#
# Phony target which is used to force executing commands for a target
#
force_build:
	-@

#
# Target to update the FD
#

fds: mbuild gen_fds

#
# Initialization target: print build information and create necessary directories
#
init: info dirs

info:
	-@echo Building ... $(MODULE_DIR)\$(MODULE_FILE) [$(ARCH)]

dirs:
	-@if not exist $(DEBUG_DIR) $(MD) $(DEBUG_DIR)
	-@if not exist $(OUTPUT_DIR) $(MD) $(OUTPUT_DIR)


strdefs:
	-@$(CP) $(DEBUG_DIR)\AutoGen.h $(DEBUG_DIR)\$(MODULE_NAME)StrDefs.h

#
# GenLibsTarget
#
gen_libs:
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\BaseDebugLibNull\BaseDebugLibNull\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\BasePcdLibNull\BasePcdLibNull\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\BaseMemoryLib\BaseMemoryLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\BaseLib\BaseLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\UefiBootServicesTableLib\UefiBootServicesTableLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\UefiMemoryAllocationLib\UefiMemoryAllocationLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\BasePrintLib\BasePrintLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\UefiRuntimeServicesTableLib\UefiRuntimeServicesTableLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\UefiDevicePathLib\UefiDevicePathLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdeModulePkg\Library\UefiHiiServicesLib\UefiHiiServicesLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\UefiLib\UefiLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\UefiApplicationEntryPoint\UefiApplicationEntryPoint\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdeModulePkg\Library\UefiSortLib\UefiSortLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdeModulePkg\Library\UefiHiiLib\UefiHiiLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\UefiFileHandleLib\UefiFileHandleLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\ShellPkg\Library\UefiShellCEntryLib\UefiShellCEntryLib\Makefile
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\ShellPkg\Library\UefiShellLib\UefiShellLib\Makefile
	@cd $(MODULE_BUILD_DIR)

#
# Build Flash Device Image
#
gen_fds:
	@"$(MAKE)" $(MAKE_FLAGS) -f $(BUILD_DIR)\Makefile fds
	@cd $(MODULE_BUILD_DIR)

!INCLUDE $(MODULE_BUILD_DIR)\dependency
!INCLUDE $(MODULE_BUILD_DIR)\deps_target

#
# Individual Object Build Targets
#
$(OBJLIST_0):  \
	$(MAKE_FILE) \
	$(WORKSPACE)\$(MODULE_NAME).c \
	$(DEBUG_DIR)\AutoGen.h \
	$(WORKSPACE)\oid_registry.c \
	$(DEBUG_DIR)\AutoGen.c \
	$(WORKSPACE)\asn1_ber_decoder.c \
	$(WORKSPACE)\x509.c
	"$(CC)" /Fo$(DEST_DIR_OUTPUT)\.\ $(DEPS_FLAGS) $(CC_FLAGS) $(INC) $(MODULE_DIR)\$(MODULE_NAME).c $(MODULE_DIR)\oid_registry.c $(DEBUG_DIR)\AutoGen.c $(MODULE_DIR)\asn1_ber_decoder.c $(MODULE_DIR)\x509.c

$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(OBJECT_FILES)
$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(OBJECT_FILES_LIST)
	"$(SLINK)" $(SLINK_FLAGS) /OUT:$(OUTPUT_DIR)\$(MODULE_NAME).lib @$(OBJECT_FILES_LIST)

$(DEBUG_DIR)\$(MODULE_NAME).dll : $(MAKE_FILE)
$(DEBUG_DIR)\$(MODULE_NAME).dll : $(STATIC_LIBRARY_FILES)
$(DEBUG_DIR)\$(MODULE_NAME).dll : $(STATIC_LIBRARY_FILES_LIST)
	"$(DLINK)" /OUT:$(DEBUG_DIR)\$(MODULE_NAME).dll $(DLINK_FLAGS) $(DLINK2_FLAGS) $(DLINK_SPATH) @$(STATIC_LIBRARY_FILES_LIST)
	"$(DLINK)" /OUT:$(DEBUG_DIR)\$(MODULE_NAME).dll $(DLINK_FLAGS) $(DLINK_SPATH) @$(STATIC_LIBRARY_FILES_LIST)

$(OUTPUT_DIR)\$(MODULE_NAME).exe : $(DEBUG_DIR)\$(MODULE_NAME).dll
	"$(GENFW)" -e $(MODULE_TYPE) -o $(OUTPUT_DIR)\$(MODULE_NAME).exe $(DEBUG_DIR)\$(MODULE_NAME).dll $(GENFW_FLAGS)
	$(CP) $(OUTPUT_DIR)\$(MODULE_NAME).exe $(DEBUG_DIR)
	$(CP) $(OUTPUT_DIR)\$(MODULE_NAME).exe $(BIN_DIR)\$(MODULE_NAME_GUID).exe
	-$(CP) $(DEBUG_DIR)\*.map $(OUTPUT_DIR)
	-$(CP) $(DEBUG_DIR)\*.pdb $(OUTPUT_DIR)



#
# clean all intermediate files
#
clean:
	if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
		$(RM) AutoGenTimeStamp

#
# clean all generated files
#
cleanall:
	if exist $(DEBUG_DIR) $(RD) $(DEBUG_DIR)
	if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
	$(RM) *.pdb *.idb > NUL 2>&1
	$(RM) $(BIN_DIR)\$(MODULE_NAME).exe
	$(RM) AutoGenTimeStamp

#
# clean all dependent libraries built
#
cleanlib:
	-@if exist $(BIN_DIR)\MdePkg\Library\BaseDebugLibNull\BaseDebugLibNull\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\BaseDebugLibNull\BaseDebugLibNull\Makefile cleanall
	-@if exist $(BIN_DIR)\MdePkg\Library\BasePcdLibNull\BasePcdLibNull\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\BasePcdLibNull\BasePcdLibNull\Makefile cleanall
	-@if exist $(BIN_DIR)\MdePkg\Library\BaseMemoryLib\BaseMemoryLib\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\BaseMemoryLib\BaseMemoryLib\Makefile cleanall
	-@if exist $(BIN_DIR)\MdePkg\Library\BaseLib\BaseLib\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\BaseLib\BaseLib\Makefile cleanall
	-@if exist $(BIN_DIR)\MdePkg\Library\UefiBootServicesTableLib\UefiBootServicesTableLib\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\UefiBootServicesTableLib\UefiBootServicesTableLib\Makefile cleanall
	-@if exist $(BIN_DIR)\MdePkg\Library\UefiMemoryAllocationLib\UefiMemoryAllocationLib\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\UefiMemoryAllocationLib\UefiMemoryAllocationLib\Makefile cleanall
	-@if exist $(BIN_DIR)\MdePkg\Library\BasePrintLib\BasePrintLib\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\BasePrintLib\BasePrintLib\Makefile cleanall
	-@if exist $(BIN_DIR)\MdePkg\Library\UefiRuntimeServicesTableLib\UefiRuntimeServicesTableLib\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\UefiRuntimeServicesTableLib\UefiRuntimeServicesTableLib\Makefile cleanall
	-@if exist $(BIN_DIR)\MdePkg\Library\UefiDevicePathLib\UefiDevicePathLib\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\UefiDevicePathLib\UefiDevicePathLib\Makefile cleanall
	-@if exist $(BIN_DIR)\MdeModulePkg\Library\UefiHiiServicesLib\UefiHiiServicesLib\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdeModulePkg\Library\UefiHiiServicesLib\UefiHiiServicesLib\Makefile cleanall
	-@if exist $(BIN_DIR)\MdePkg\Library\UefiLib\UefiLib\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\UefiLib\UefiLib\Makefile cleanall
	-@if exist $(BIN_DIR)\MdePkg\Library\UefiApplicationEntryPoint\UefiApplicationEntryPoint\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\UefiApplicationEntryPoint\UefiApplicationEntryPoint\Makefile cleanall
	-@if exist $(BIN_DIR)\MdeModulePkg\Library\UefiSortLib\UefiSortLib\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdeModulePkg\Library\UefiSortLib\UefiSortLib\Makefile cleanall
	-@if exist $(BIN_DIR)\MdeModulePkg\Library\UefiHiiLib\UefiHiiLib\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdeModulePkg\Library\UefiHiiLib\UefiHiiLib\Makefile cleanall
	-@if exist $(BIN_DIR)\MdePkg\Library\UefiFileHandleLib\UefiFileHandleLib\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\MdePkg\Library\UefiFileHandleLib\UefiFileHandleLib\Makefile cleanall
	-@if exist $(BIN_DIR)\ShellPkg\Library\UefiShellCEntryLib\UefiShellCEntryLib\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\ShellPkg\Library\UefiShellCEntryLib\UefiShellCEntryLib\Makefile cleanall
	-@if exist $(BIN_DIR)\ShellPkg\Library\UefiShellLib\UefiShellLib\Makefile "$(MAKE)" $(MAKE_FLAGS) -f $(BIN_DIR)\ShellPkg\Library\UefiShellLib\UefiShellLib\Makefile cleanall
	@cd $(MODULE_BUILD_DIR)

