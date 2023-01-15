class EXEPROJECTINFO():
    def __init__(self, ea):
        self.__lpHeader = ea

        self.szVbMagic = ida_bytes.get_dword(ea)
        self.wRuntimeBuild = ida_bytes.get_word(ea + 4)
        self.szLangDll = ida_bytes.get_strlit_contents(ea + 6, -1, STRTYPE_C)
        self.szSecLangDll = ida_bytes.get_strlit_contents(ea + 20, -1, STRTYPE_C)
        self.wRuntimeRevision = ida_bytes.get_word(ea + 34)
        self.dwLCID = ida_bytes.get_dword(ea + 36)
        self.dwSecLCID = ida_bytes.get_dword(ea + 40)
        self.lpSubMain = ida_bytes.get_dword(ea + 44)
        self.lpProjectData = ida_bytes.get_dword(ea + 48)
        self.fMdlIntCtls = ida_bytes.get_dword(ea + 52)
        self.fMdlIntCtls2 = ida_bytes.get_dword(ea + 56)
        self.dwThreadFlags = ida_bytes.get_dword(ea + 60)
        self.dwThreadCount = ida_bytes.get_dword(ea + 64)
        self.wFormCount = ida_bytes.get_word(ea + 68)
        self.wExternalCount = ida_bytes.get_word(ea + 70)
        self.dwThunkCount = ida_bytes.get_dword(ea + 72)
        self.lpGuiTable = ida_bytes.get_dword(ea + 76)
        self.lpExternalTable = ida_bytes.get_dword(ea + 80)
        self.lpComRegisterData = ida_bytes.get_dword(ea + 84)
        self.bSZProjectDescription = ida_bytes.get_dword(ea + 88)
        self.bSZProjectExeName = ida_bytes.get_dword(ea + 92)
        self.bSZProjectHelpFile = ida_bytes.get_dword(ea + 96)
        self.bSZProjectName = ida_bytes.get_dword(ea + 100)

    def getProjectDescription(self):
        return ida_bytes.get_strlit_contents(self.__lpHeader + self.bSZProjectDescription, -1, STRTYPE_C)

    def getProjectExeName(self):
        return ida_bytes.get_strlit_contents(self.__lpHeader + self.bSZProjectExeName, -1, STRTYPE_C)

    def getProjectHelpFile(self):
        return ida_bytes.get_strlit_contents(self.__lpHeader + self.bSZProjectHelpFile, -1, STRTYPE_C)

    def getProjectName(self):
        return ida_bytes.get_strlit_contents(self.__lpHeader + self.bSZProjectName, -1, STRTYPE_C)

vbHdr = EXEPROJECTINFO(get_screen_ea())
print(vbHdr.getProjectName())
