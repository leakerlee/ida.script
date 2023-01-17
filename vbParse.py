class EXEPROJECTINFO():
    __structName = "VB_EXEPROJECTINFO"

    def __init__(self, ea):
        self.__lpBase = ea

        self.szVbMagic = ida_bytes.get_strlit_contents(ea, 4, STRTYPE_C)                # 0x0 szVbMagic “VB5!” String
        self.wRuntimeBuild = ida_bytes.get_word(ea + 4)                                 # 0x4 wRuntimeBuild Build of the VB6 Runtime
        self.szLangDll = ida_bytes.get_strlit_contents(ea + 6, -1, STRTYPE_C)           # 0x6 szLangDll Language Extension DLL
        self.szSecLangDll = ida_bytes.get_strlit_contents(ea + 20, -1, STRTYPE_C)       # 0x14 szSecLangDll 2nd Language Extension DLL
        self.wRuntimeRevision = ida_bytes.get_word(ea + 34)                             # 0x22 wRuntimeRevision Internal Runtime Revision
        self.dwLCID = ida_bytes.get_dword(ea + 36)                                      # 0x24 dwLCID LCID of Language DLL
        self.dwSecLCID = ida_bytes.get_dword(ea + 40)                                   # 0x28 dwSecLCID LCID of 2nd Language DLL
        self.lpSubMain = ida_bytes.get_dword(ea + 44)                                   # 0x2C lpSubMain Pointer to Sub Main Code
        self.lpProjectData = ida_bytes.get_dword(ea + 48)                               # 0x30 lpProjectData Pointer to Project Data
        self.fMdlIntCtls = ida_bytes.get_dword(ea + 52)                                 # 0x34 fMdlIntCtls VB Control Flags for IDs < 32
        self.fMdlIntCtls2 = ida_bytes.get_dword(ea + 56)                                # 0x38 fMdlIntCtls2 VB Control Flags for IDs > 32
        self.dwThreadFlags = ida_bytes.get_dword(ea + 60)                               # 0x3C dwThreadFlags Threading Mode
        self.dwThreadCount = ida_bytes.get_dword(ea + 64)                               # 0x40 dwThreadCount Threads to support in pool
        self.wFormCount = ida_bytes.get_word(ea + 68)                                   # 0x44 wFormCount Number of forms present
        self.wExternalCount = ida_bytes.get_word(ea + 70)                               # 0x46 wExternalCount Number of external controls
        self.dwThunkCount = ida_bytes.get_dword(ea + 72)                                # 0x48 dwThunkCount Number of thunks to create
        self.lpGuiTable = ida_bytes.get_dword(ea + 76)                                  # 0x4C lpGuiTable Pointer to GUI Table
        self.lpExternalTable = ida_bytes.get_dword(ea + 80)                             # 0x50 lpExternalTable Pointer to External Table
        self.lpComRegisterData = ida_bytes.get_dword(ea + 84)                           # 0x54 lpComRegisterData Pointer to COM Information
        self.bSZProjectDescription = ida_bytes.get_dword(ea + 88)                       # 0x58 bSZProjectDescription Offset to Project Description
        self.bSZProjectExeName = ida_bytes.get_dword(ea + 92)                           # 0x5C bSZProjectExeName Offset to Project EXE Name
        self.bSZProjectHelpFile = ida_bytes.get_dword(ea + 96)                          # 0x60 bSZProjectHelpFile Offset to Project Help File
        self.bSZProjectName = ida_bytes.get_dword(ea + 100)                             # 0x64 bSZProjectName Offset to Project Name

    def getProjectDescription(self):
        return ida_bytes.get_strlit_contents(self.__lpBase + self.bSZProjectDescription, -1, STRTYPE_C)

    def getProjectExeName(self):
        return ida_bytes.get_strlit_contents(self.__lpBase + self.bSZProjectExeName, -1, STRTYPE_C)

    def getProjectHelpFile(self):
        return ida_bytes.get_strlit_contents(self.__lpBase + self.bSZProjectHelpFile, -1, STRTYPE_C)

    def getProjectName(self):
        return ida_bytes.get_strlit_contents(self.__lpBase + self.bSZProjectName, -1, STRTYPE_C)

    def setProjectNameType(self):
        del_items(self.__lpBase + self.bSZProjectName, DELIT_SIMPLE, ida_bytes.get_max_strlit_length(self.__lpBase + self.bSZProjectName, STRTYPE_C))
        return ida_bytes.create_strlit(self.__lpBase + self.bSZProjectName, 0, STRTYPE_C)

    @staticmethod
    def size():
        return 0x68

    @staticmethod
    def createDataStructure():
        uiStructID = ida_struct.get_struc_id(EXEPROJECTINFO.__structName)
        if uiStructID != BADADDR:
            print(EXEPROJECTINFO.__structName + " exists")
            ida_struct.del_struc(ida_struct.get_struc(uiStructID))
        tidStruc = ida_struct.add_struc(BADADDR, EXEPROJECTINFO.__structName)
        if tidStruc == BADADDR:
            print("ida_struct.add_struc " + EXEPROJECTINFO.__structName + " failed")
            return False

        idc.add_struc_member(tidStruc, "szVbMagic", BADADDR, FF_STRLIT|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "wRuntimeBuild", BADADDR, FF_WORD|FF_DATA, -1, 2)
        idc.add_struc_member(tidStruc, "szLangDll", BADADDR, FF_STRLIT|FF_DATA, -1, 0xE)
        idc.add_struc_member(tidStruc, "szSecLangDll", BADADDR, FF_STRLIT|FF_DATA, -1, 0xE)
        idc.add_struc_member(tidStruc, "wRuntimeRevision", BADADDR, FF_WORD|FF_DATA, -1, 2)
        idc.add_struc_member(tidStruc, "dwLCID", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "dwSecLCID", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "lpSubMain", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "lpProjectData", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "fMdlIntCtls", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "fMdlIntCtls2", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "dwThreadFlags", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "dwThreadCount", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "wFormCount", BADADDR, FF_WORD|FF_DATA, -1, 2)
        idc.add_struc_member(tidStruc, "wExternalCount", BADADDR, FF_WORD|FF_DATA, -1, 2)
        idc.add_struc_member(tidStruc, "dwThunkCount", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "lpGuiTable", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "lpExternalTable", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "lpComRegisterData", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "bSZProjectDescription", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "bSZProjectExeName", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "bSZProjectHelpFile", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "bSZProjectName", BADADDR, FF_DWORD|FF_DATA, -1, 4)

        til, ti = idaapi.get_idati(), idaapi.tinfo_t()
        ida_typeinf.import_type(til, -1, "CLSID", )

        strRes = ida_typeinf.parse_decl(ti, til, "typedef CLSID* LPCLSID;", 0)
        print(strRes)

        if strRes is not None:
            ida_struct.set_member_tinfo(\
                ida_struct.get_struc(ida_struct.get_struc_id("VB_EXEPROJECTINFO")), ida_struct.get_member(ida_struct.get_struc(ida_struct.get_struc_id("VB_EXEPROJECTINFO")), get_member_offset(ida_struct.get_struc_id("VB_EXEPROJECTINFO"), "lpGuiTable")),\
                get_member_offset(ida_struct.get_struc_id("VB_EXEPROJECTINFO"), "lpGuiTable"),\
                ti,\
                0\
            )
        else:
            print("parse_decl failed")

    @staticmethod
    def applyDataStructure(ea):
        EXEPROJECTINFO.createDataStructure()
        del_items(ea, DELIT_SIMPLE, EXEPROJECTINFO.size())
        idc.create_struct(ea, -1, EXEPROJECTINFO.__structName)
        lpGuiTable = ida_bytes.get_dword(ea + 0x4C)
        del_items(lpGuiTable, DELIT_SIMPLE, ida_struct.get_struc_size(ida_struct.get_struc_id("GUID")))
        idc.create_struct(lpGuiTable, -1, "GUID")

class ProjectData():
    __structName = "VB_ProjectData"

    def __init__(self, ea):
        self.__lpBase = ea

        self.dwVersion = ida_bytes.get_dword(ea)                 # 0x0 dwVersion 5.00 in Hex (0x1F4). Version.
        self.lpObjectTable = ida_bytes.get_dword(ea + 0x4)             # 0x4 lpObjectTable Pointer to the Object Table
        self.dwNull = ida_bytes.get_dword(ea + 0x8)                    # 0x8 dwNull Unused value after compilation.
        self.lpCodeStart = ida_bytes.get_dword(ea + 0xC)               # 0xC lpCodeStart Points to start of code. Unused.
        self.lpCodeEnd = ida_bytes.get_dword(ea + 0x10)                 # 0x10 lpCodeEnd Points to end of code. Unused.
        self.dwDataSize = ida_bytes.get_dword(ea + 0x14)                # 0x14 dwDataSize Size of VB Object Structures. Unused.
        self.lpThreadSpace = ida_bytes.get_dword(ea + 0x18)             # 0x18 lpThreadSpace Pointer to Pointer to Thread Object.
        self.lpVbaSeh = ida_bytes.get_dword(ea + 0x1C)                  # 0x1C lpVbaSeh Pointer to VBA Exception Handler
        self.lpNativeCode = ida_bytes.get_dword(ea + 0x20)              # 0x20 lpNativeCode Pointer to .DATA section.
        self.szPathInformation = ida_bytes.get_strlit_contents(ea + 0x24, 0x210, STRTYPE_C)  # 0x24 szPathInformation Contains Path and ID string. < SP6
        self.lpExternalTable = ida_bytes.get_dword(ea + 0x234)           # 0x234 lpExternalTable Pointer to External Table.
        self.dwExternalCount = ida_bytes.get_dword(ea + 0x238)           # 0x238 dwExternalCount Objects in the External Table.

    @staticmethod
    def size():
        return 0x23C

    @staticmethod
    def createDataStructure():
        uiStructID = ida_struct.get_struc_id(ProjectData.__structName)
        if uiStructID != BADADDR:
            print(ProjectData.__structName + " exists")
            ida_struct.del_struc(ida_struct.get_struc(uiStructID))
        tidStruc = ida_struct.add_struc(BADADDR, ProjectData.__structName)
        if tidStruc == BADADDR:
            print("ida_struct.add_struc " + ProjectData.__structName + " failed")
            return False

        idc.add_struc_member(tidStruc, "dwVersion", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "lpObjectTable", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "dwNull", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "lpCodeStart", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "lpCodeEnd", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "dwDataSize", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "lpThreadSpace", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "lpVbaSeh", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "lpNativeCode", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "szPathInformation", BADADDR, FF_STRLIT|FF_DATA, -1, 0x210)
        idc.add_struc_member(tidStruc, "lpExternalTable", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "dwExternalCount", BADADDR, FF_DWORD|FF_DATA, -1, 4)

    @staticmethod
    def applyDataStructure(ea):
        ProjectData.createDataStructure()
        del_items(ea, DELIT_SIMPLE, ProjectData.size())
        idc.create_struct(ea, -1, ProjectData.__structName)

class ObjectTable():
    __structName = "VB_ObjectTable"

    def __init__(self, ea):
        self.__lpBase = ea

        self.lpHeapLink = ida_bytes.get_dword(ea)          # 0x0 lpHeapLink Unused after compilation, always 0.
        self.lpExecProj = ida_bytes.get_dword(ea + 0x4)          # 0x4 lpExecProj Pointer to VB Project Exec COM Object.
        self.lpProjectInfo2 = ida_bytes.get_dword(ea + 0x8)      # 0x8 lpProjectInfo2 Secondary Project Information
        self.dwReserved = ida_bytes.get_dword(ea + 0xC)          # 0xC dwReserved Always set to -1 after compiling. Unused
        self.dwNull = ida_bytes.get_dword(ea + 0x10)              # 0x10 dwNull Not used in compiled mode.
        self.lpProjectObject = ida_bytes.get_dword(ea + 0x14)     # 0x14 lpProjectObject Pointer to in-memory Project Data.
        self.uuidObject = ida_bytes.get_bytes(ea + 0x18, 0x10)  # 0x18 uuidObject GUID of the Object Table.
        self.fCompileState = ida_bytes.get_word(ea + 0x28)       # 0x28 fCompileState Internal flag used during compilation.
        self.wTotalObjects = ida_bytes.get_word(ea + 0x2A)       # 0x2A wTotalObjects Total objects present in Project.
        self.wCompiledObjects = ida_bytes.get_word(ea + 0x2C)    # 0x2C wCompiledObjects Equal to above after compiling.
        self.wObjectsInUse = ida_bytes.get_word(ea + 0x2E)       # 0x2E wObjectsInUse Usually equal to above after compile.
        self.lpObjectArray = ida_bytes.get_dword(ea + 0x30)       # 0x30 lpObjectArray Pointer to Object Descriptors
        self.fIdeFlag = ida_bytes.get_dword(ea + 0x34)            # 0x34 fIdeFlag Flag/Pointer used in IDE only.
        self.lpIdeData = ida_bytes.get_dword(ea + 0x38)           # 0x38 lpIdeData Flag/Pointer used in IDE only.
        self.lpIdeData2 = ida_bytes.get_dword(ea + 0x3C)          # 0x3C lpIdeData2 Flag/Pointer used in IDE only.
        self.lpszProjectName = ida_bytes.get_dword(ea + 0x40)     # 0x40 lpszProjectName Pointer to Project Name.
        self.dwLcid = ida_bytes.get_dword(ea + 0x44)              # 0x44 dwLcid LCID of Project.
        self.dwLcid2 = ida_bytes.get_dword(ea + 0x48)             # 0x48 dwLcid2 Alternate LCID of Project.
        self.lpIdeData3 = ida_bytes.get_dword(ea + 0x4C)          # 0x4C lpIdeData3 Flag/Pointer used in IDE only.
        self.dwIdentifier = ida_bytes.get_dword(ea + 0x50)        # 0x50 dwIdentifier Template Version of Structure.

    @staticmethod
    def size():
        return 0x54

    @staticmethod
    def createDataStructure():
        uiStructID = ida_struct.get_struc_id(ObjectTable.__structName)
        if uiStructID != BADADDR:
            print(ObjectTable.__structName + " exists")
            ida_struct.del_struc(ida_struct.get_struc(uiStructID))
        tidStruc = ida_struct.add_struc(BADADDR, ObjectTable.__structName)
        if tidStruc == BADADDR:
            print("ida_struct.add_struc " + ObjectTable.__structName + " failed")
            return False

        til = idaapi.get_idati()
        ida_typeinf.import_type(til, -1, "GUID", )

        idc.add_struc_member(tidStruc, "lpHeapLink", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "lpExecProj", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "lpProjectInfo2", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "dwReserved", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "dwNull", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "lpProjectObject", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(ida_struct.get_struc_id(ObjectTable.__structName), "uuidObject", BADADDR, FF_STRUCT|FF_DATA, ida_struct.get_struc_id("GUID"), 0x10)
        idc.add_struc_member(tidStruc, "fCompileState", BADADDR, FF_WORD|FF_DATA, -1, 2)
        idc.add_struc_member(tidStruc, "wTotalObjects", BADADDR, FF_WORD|FF_DATA, -1, 2)
        idc.add_struc_member(tidStruc, "wCompiledObjects", BADADDR, FF_WORD|FF_DATA, -1, 2)
        idc.add_struc_member(tidStruc, "wObjectsInUse", BADADDR, FF_WORD|FF_DATA, -1, 2)
        idc.add_struc_member(tidStruc, "lpObjectArray", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "fIdeFlag", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "lpIdeData", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "lpIdeData2", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "lpszProjectName", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "dwLcid", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "dwLcid2", BADADDR, FF_DWORD|FF_DATA, -1, 4)
        idc.add_struc_member(tidStruc, "lpIdeData3", BADADDR, FF_0OFF|FF_1OFF|FF_DWORD|FF_DATA, 0, 4)
        idc.add_struc_member(tidStruc, "dwIdentifier", BADADDR, FF_DWORD|FF_DATA, -1, 4)

    @staticmethod
    def applyDataStructure(ea):
        ObjectTable.createDataStructure()
        del_items(ea, DELIT_SIMPLE, ObjectTable.size())
        idc.create_struct(ea, -1, ObjectTable.__structName)

class ProjectData2():
    def __init__(self, ea):
        self.__lpBase = ea

        self.lpHeapLink = ida_bytes.get_dword(ea)            # 0x0 lpHeapLink Unused after compilation, always 0.
        self.lpObjectTable = ida_bytes.get_dword(ea + 0x4)         # 0x4 lpObjectTable Back-Pointer to the Object Table.
        self.dwReserved = ida_bytes.get_dword(ea + 0x8)            # 0x8 dwReserved Always set to -1 after compiling. Unused
        self.dwUnused = ida_bytes.get_dword(ea + 0xC)              # 0xC dwUnused Not written or read in any case.
        # points to array of pointers to `PrivateObjectDescriptor`
        self.lpObjectList = ida_bytes.get_dword(ea + 0x10)          # 0x10 lpObjectList Pointer to Object Descriptor Pointers.
        self.dwUnused2 = ida_bytes.get_dword(ea + 0x14)             # 0x14 dwUnused2 Not written or read in any case.
        self.szProjectDescription = ida_bytes.get_dword(ea + 0x18)  # 0x18 szProjectDescription Pointer to Project Description
        self.szProjectHelpFile = ida_bytes.get_dword(ea + 0x1C)     # 0x1C szProjectHelpFile Pointer to Project Help File
        self.dwReserved2 = ida_bytes.get_dword(ea + 0x20)           # 0x20 dwReserved2 Always set to -1 after compiling. Unused
        self.dwHelpContextId = ida_bytes.get_dword(ea + 0x24)       # 0x24 dwHelpContextId Help Context ID set in Project Settings.

class PublicObjectDescriptor():
    def __init__(self, ea):
        self.__lpBase = ea

        self.lpObjectInfo = ida_bytes.get_dword(ea)    # 0x0 lpObjectInfo Pointer to the Object Info for this Object.
        self.dwReserved = ida_bytes.get_dword(ea + 0x4)      # 0x4 dwReserved Always set to -1 after compiling.
        self.lpPublicBytes = ida_bytes.get_dword(ea + 0x8)   # 0x8 lpPublicBytes Pointer to Public Variable Size integers.
        self.lpStaticBytes = ida_bytes.get_dword(ea + 0xC)   # 0xC lpStaticBytes Pointer to Static Variable Size integers.
        self.lpModulePublic = ida_bytes.get_dword(ea + 0x10)  # 0x10 lpModulePublic Pointer to Public Variables in DATA section
        self.lpModuleStatic = ida_bytes.get_dword(ea + 0x14)  # 0x14 lpModuleStatic Pointer to Static Variables in DATA section
        self.lpszObjectName = ida_bytes.get_dword(ea + 0x18)  # 0x18 lpszObjectName Name of the Object.
        self.dwMethodCount = ida_bytes.get_dword(ea + 0x1C)   # 0x1C dwMethodCount Number of Methods in Object.
        self.lpMethodNames = ida_bytes.get_dword(ea + 0x20)   # 0x20 lpMethodNames If present, pointer to Method names array.
        self.bStaticVars = ida_bytes.get_dword(ea + 0x24)     # 0x24 bStaticVars Offset to where to copy Static Variables.
        self.fObjectType = ida_bytes.get_dword(ea + 0x28)     # 0x28 fObjectType Flags defining the Object Type.
        self.dwNull = ida_bytes.get_dword(ea + 0x2C)          # 0x2C dwNull Not valid after compilation.

    @staticmethod
    def size():
        return 0x30

class ObjectInfo():
    def __init__(self, ea):
        self.__lpBase = ea

        self.wRefCount = ida_bytes.get_word(ea)        # 0x0 wRefCount Always 1 after compilation.
        self.wObjectIndex = ida_bytes.get_word(ea + 0x2)     # 0x2 wObjectIndex Index of this Object.
        self.lpObjectTable = ida_bytes.get_dword(ea + 0x4)    # 0x4 lpObjectTable Pointer to the Object Table
        self.lpIdeData = ida_bytes.get_dword(ea + 0x8)        # 0x8 lpIdeData Zero after compilation. Used in IDE only.
        self.lpPrivateObject = ida_bytes.get_dword(ea + 0xC)  # 0xC lpPrivateObject Pointer to Private Object Descriptor.
        self.dwReserved = ida_bytes.get_dword(ea + 0x10)       # 0x10 dwReserved Always -1 after compilation.
        self.dwNull = ida_bytes.get_dword(ea + 0x14)           # 0x14 dwNull Unused.
        self.lpObject = ida_bytes.get_dword(ea + 0x18)         # 0x18 lpObject Back-Pointer to Public Object Descriptor.
        self.lpProjectData = ida_bytes.get_dword(ea + 0x1C)    # 0x1C lpProjectData Pointer to in-memory Project Object.
        self.wMethodCount = ida_bytes.get_word(ea + 0x20)     # 0x20 wMethodCount Number of Methods
        self.wMethodCount2 = ida_bytes.get_word(ea + 0x22)    # 0x22 wMethodCount2 Zeroed out after compilation. IDE only.
        self.lpMethods = ida_bytes.get_dword(ea + 0x24)        # 0x24 lpMethods Pointer to Array of Methods.
        self.wConstants = ida_bytes.get_word(ea + 0x28)       # 0x28 wConstants Number of Constants in Constant Pool.
        self.wMaxConstants = ida_bytes.get_word(ea + 0x2A)    # 0x2A wMaxConstants Constants to allocate in Constant Pool.
        self.lpIdeData2 = ida_bytes.get_dword(ea + 0x2C)       # 0x2C lpIdeData2 Valid in IDE only.
        self.lpIdeData3 = ida_bytes.get_dword(ea + 0x30)       # 0x30 lpIdeData3 Valid in IDE only.
        self.lpConstants = ida_bytes.get_dword(ea + 0x34)      # 0x34 lpConstants Pointer to Constants Pool.

    @staticmethod
    def size():
        return 0x38

class OptionalObjectInfo():
    def __init__(self, ea):
        self.__lpBase = ea

        self.dwObjectGuiGuids = ida_bytes.get_dword(ea)         # 0x0 Number of ObjectGUI GUIDs (2 for Designer)
        self.lpObjectCLSID = ida_bytes.get_dword(ea + 0x4)            # 0x4 Pointer to object CLSID
        self.dwNull = ida_bytes.get_dword(ea + 0x8)                   # 0x8
        self.lpGuidObjectGUITable = ida_bytes.get_dword(ea + 0xC)     # 0xC Pointer to pointers of guidObjectGUI
        self.dwObjectDefaultIIDCount = ida_bytes.get_dword(ea + 0x10)  # 0x10 Number of DefaultIIDs
        self.lpObjectEventsIIDTable = ida_bytes.get_dword(ea + 0x14)   # 0x14 Pointer to pointers of EventsIID
        self.dwObjectEventsIIDCount = ida_bytes.get_dword(ea + 0x18)   # 0x18 Number of EventsIID
        self.lpObjectDefaultIIDTable = ida_bytes.get_dword(ea + 0x1C)  # 0x1C Pointer to pointers of DefaultIID
        self.dwControlCount = ida_bytes.get_dword(ea + 0x20)           # 0x20 dwControlCount Number of Controls in array below.
        self.lpControls = ida_bytes.get_dword(ea + 0x24)               # 0x24 lpControls Pointer to Controls Array.
        self.wMethodLinkCount = ida_bytes.get_word(ea + 0x28)         # 0x28 wMethodLinkCount Number of Method Links
        self.wPCodeCount = ida_bytes.get_word(ea + 0x2A)              # 0x2A wPCodeCount Number of P-Codes used by this Object.
        self.bWInitializeEvent = ida_bytes.get_word(ea + 0x2C)        # 0x2C bWInitializeEvent Offset to Initialize Event from Event Table.
        self.bWTerminateEvent = ida_bytes.get_word(ea + 0x2E)         # 0x2E bWTerminateEvent Offset to Terminate Event in Event Table.
        self.lpMethodLinkTable = ida_bytes.get_dword(ea + 0x30)        # 0x30 lpMethodLinkTable Pointer to pointers of MethodLink
        self.lpBasicClassObject = ida_bytes.get_dword(ea + 0x34)       # 0x34 lpBasicClassObject Pointer to in-memory Class Objects.
        self.dwNull3 = ida_bytes.get_dword(ea + 0x38)                  # 0x38 dwNull3 Unused.
        self.lpIdeData = ida_bytes.get_dword(ea + 0x3C)                # 0x3C lpIdeData Only valid in IDE.

OBJECT_HAS_OPTIONAL_INFO = 0x1

vbHdr = EXEPROJECTINFO(get_screen_ea())
EXEPROJECTINFO.applyDataStructure(get_screen_ea())
print(vbHdr.getProjectName())
projData = ProjectData(vbHdr.lpProjectData)
ProjectData.applyDataStructure(vbHdr.lpProjectData)

print(hex(projData.lpObjectTable))
objTable = ObjectTable(projData.lpObjectTable)
ObjectTable.applyDataStructure(projData.lpObjectTable)
print(objTable.wTotalObjects)

projData2 = ProjectData2(objTable.lpProjectInfo2)
print(hex(projData2.lpObjectTable))

print('#######################')
for i in range(objTable.wTotalObjects):
    print('************')
    va = objTable.lpObjectArray + (i * PublicObjectDescriptor.size())
    print(hex(va))
    pubObjDesc = PublicObjectDescriptor(va)
    print(ida_bytes.get_strlit_contents(pubObjDesc.lpszObjectName, -1, STRTYPE_C))
    objInfo = ObjectInfo(pubObjDesc.lpObjectInfo)
    if (pubObjDesc.fObjectType & OBJECT_HAS_OPTIONAL_INFO) != 0x0:
        va = pubObjDesc.lpObjectInfo + ObjectInfo.size()
        optObjInfo = OptionalObjectInfo(va)
        print(hex(optObjInfo.lpMethodLinkTable))
    else:
        print("OBJECT HAS NO OPTIONAL INFO")
        break


