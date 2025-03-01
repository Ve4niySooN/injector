unit MemoryUtils;

interface

uses
  Windows, SysUtils, TlHelp32, PsAPI;

type
  INJECT_TYPE = (LoadLibrary, LdrLoadDll, APCInjection, ManualMapping, ReflectiveDLLInjection, AppInit_DLLs);

  TInject = class
  private
    FProcessID: DWORD;
    FDLLPath: AnsiString;
    FInjectType: INJECT_TYPE;
    function GetProcessID(ProcessName: string): DWORD;
    function IsModuleLoaded(ModulePath: ansistring; ProcessID: DWORD): Boolean;
  public
    constructor Create(InjectType: INJECT_TYPE; ProcessName, DLLPath: ansistring);
    function InjectDLL: Boolean;
  end;

implementation

type
  TNtCreateThreadEx = function(
    ThreadHandle: PHANDLE;
    DesiredAccess: ACCESS_MASK;
    ObjectAttributes: Pointer;
    ProcessHandle: THANDLE;
    lpStartAddress: Pointer;
    lpParameter: Pointer;
    CreateSuspended: BOOL;
    dwStackSize: DWORD;
    Unknown1: Pointer;
    Unknown2: Pointer;
    Unknown3: Pointer): HRESULT; stdcall;

const
  THREAD_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED or SYNCHRONIZE or $3FF;

function OpenThread(dwDesiredAccess: DWORD; bInheritHandle: BOOL;
  dwThreadId: DWORD): THandle; stdcall; external kernel32;

constructor TInject.Create(InjectType: INJECT_TYPE; ProcessName, DLLPath: ansistring);
begin
  FInjectType := InjectType;
  FProcessID  := GetProcessID(string(ProcessName));
  FDLLPath    := DLLPath;
end;

function TInject.GetProcessID(ProcessName: string): DWORD;
var
  Handle: THandle;
  Process: TProcessEntry32;
  GotProcess: Boolean;
begin
  Handle := CreateToolHelp32SnapShot(TH32CS_SNAPALL, 0);
  Process.dwSize := SizeOf(Process);
  GotProcess := Process32First(Handle, Process);
  if GotProcess and (Process.szExeFile <> ProcessName) then
    repeat
      GotProcess := Process32Next(Handle, Process);
    until (not GotProcess) or (Process.szExeFile = ProcessName);
  if GotProcess then
    Result := Process.th32ProcessID
  else
    Result := 0;
  CloseHandle(Handle);
end;

function TInject.IsModuleLoaded(ModulePath: ansistring; ProcessID: DWORD): Boolean;
var
  hSnapshot: THandle;
  ModuleEntry32: TModuleEntry32;
  szExePath: ansistring;
begin
  Result := False;
  hSnapshot := CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessID);
  if (hSnapshot <> -1) then
  begin
    ModuleEntry32.dwSize := SizeOf(TModuleEntry32);
    if (Module32First(hSnapshot, ModuleEntry32)) then
      repeat
        szExePath := ansistring(ModuleEntry32.szExePath);
        if szExePath = ModulePath then
        begin
          Result := True;
          Break;
        end;
      until not Module32Next(hSnapshot, ModuleEntry32);
    CloseHandle(hSnapshot);
  end;
end;

function TInject.InjectDLL: Boolean;
var
  hProcess, hThread: THandle;
  pRemoteMemory, pLoadLibrary, pLdrLoadDll: Pointer;
  BytesWritten: SIZE_T;
  ThreadEntry: TThreadEntry32;
  Snapshot: THandle;
  NtCreateThreadEx: TNtCreateThreadEx;
begin
  Result := False;

  if FProcessID = 0 then Exit;

  if IsModuleLoaded(FDLLPath, FProcessID) then
  begin
    Result := True;
    Exit;
  end;

  NtCreateThreadEx := GetProcAddress(GetModuleHandleW('ntdll'), 'NtCreateThreadEx');
  if (@NtCreateThreadEx = nil) then Exit;

  hProcess := OpenProcess(MAXIMUM_ALLOWED, False, FProcessID);
  if hProcess = 0 then Exit;

  try
    case FInjectType of
      LoadLibrary:
      begin
        // Стандартный способ. Используется ВЕЗДЕ, его приводят в пример в обучающих книгах,
        // это безопасно но перехватывается *ВСЕМ*, и мишура подготовительных действий не
        // всегда нужна, по этому можете смотреть сразу в сторону другого стандартного способа
        // с использованием LdrLoadDll напрямую. LoadLibrary всё-равно его вызывает к конечном итоге

        pRemoteMemory := VirtualAllocEx(hProcess, nil, Length(FDLLPath), MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if pRemoteMemory = nil then Exit;

        try
          if not WriteProcessMemory(hProcess, pRemoteMemory, PAnsiChar(FDLLPath), Length(FDLLPath), BytesWritten) then Exit;

          pLoadLibrary := GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA');
          if pLoadLibrary = nil then Exit;

          hThread := NtCreateThreadEx(@hThread, MAXIMUM_ALLOWED, nil, hProcess, pLoadLibrary, pRemoteMemory, false, 0, 0, 0, 0);
          if hThread <> 0 then Exit;

          WaitForSingleObject(hThread, INFINITE);
          CloseHandle(hThread);
          Result := True;
        finally
          VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        end;
      end;

      LdrLoadDll:
      begin
        // Для инжекта во всем лучше, чем LoadLibrary, но требует указания полного пути к .dll файлу

        pLdrLoadDll := GetProcAddress(GetModuleHandle('ntdll.dll'), 'LdrLoadDll');
        if pLdrLoadDll = nil then Exit;

        pRemoteMemory := VirtualAllocEx(hProcess, nil, Length(FDLLPath), MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if pRemoteMemory = nil then Exit;

        try
          if not WriteProcessMemory(hProcess, pRemoteMemory, PAnsiChar(FDLLPath), Length(FDLLPath), BytesWritten) then Exit;

          //hThread := CreateRemoteThread(hProcess, nil, 0, pLdrLoadDll, pRemoteMemory, 0, dwThreadId);
          hThread := NtCreateThreadEx(@hThread, MAXIMUM_ALLOWED, nil, hProcess, pLdrLoadDll, pRemoteMemory, false, 0, 0, 0, 0);
          if hThread <> 0 then Exit;

          WaitForSingleObject(hThread, INFINITE);
          CloseHandle(hThread);
          Result := True;
        finally
          VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        end;
      end;

      APCInjection:
      begin
        // Не будет работать если поток не находится в "alertable state", очередь APC
        // переполнена или поток завершился раньше, чем APC.
        // https://learn.microsoft.com/en-us/windows/win32/fileio/alertable-i-o

        pLoadLibrary := GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA');
        if pLoadLibrary = nil then Exit;

        pRemoteMemory := VirtualAllocEx(hProcess, nil, Length(FDLLPath), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE);
        if pRemoteMemory = nil then Exit;

        if not WriteProcessMemory(hProcess, pRemoteMemory, PAnsiChar(FDLLPath), Length(FDLLPath), BytesWritten) then Exit;

        Snapshot := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if Snapshot = INVALID_HANDLE_VALUE then Exit;

        try
          ThreadEntry.dwSize := SizeOf(ThreadEntry);
          if Thread32First(Snapshot, ThreadEntry) then
          begin
            repeat
              if ThreadEntry.th32OwnerProcessID = FProcessID then
              begin
                hThread := OpenThread($0010, False, ThreadEntry.th32ThreadID);
                if hThread <> 0 then
                begin
                  try
                    QueueUserAPC(pLoadLibrary, hThread, ULONG_PTR(pRemoteMemory));
                    Sleep(500);

                    if IsModuleLoaded(FDLLPath, FProcessID) then
                    begin
                      CloseHandle(hThread);
                      Break;
                    end;
                  finally

                  end;
                end;
              end;
            until not Thread32Next(Snapshot, ThreadEntry);
          end;
        finally
          CloseHandle(Snapshot);
          VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        end;
      end;

      ManualMapping:
      begin
        // Раздует код в ахуй, вырезаем. Часто требуется править код под определённый
        // процесс, не подходит для необдуманного инжекта, в лучшем случае крашнет процесс
        // в худшем свалитесь в бсод.
        raise Exception.Create('Не поддерживается в данном примере');
      end;

      ReflectiveDLLInjection:
      begin
        // Проще, чем ручной мапинг, но нужно модицифировать саму .dll, внедряя в неё шелл.
        // Не подходит для массового инжекта чего-угодно во что-угодно.
        raise Exception.Create('Не поддерживается в данном примере');
      end;

      AppInit_DLLs:
      begin
        // Инжект во все процессы. Опасно, требует проверки процесса в самой .dll
        // во избежании краша сторонних процессов; блокируется *ВСЕМ*, от антивирусов
        // до античитов; плохому не учим, потому вырезаем. Если интересно, то вот:
        // https://learn.microsoft.com/ru-ru/windows/win32/win7appqual/appinit-dlls-in-windows-7-and-windows-server-2008-r2
        raise Exception.Create('Не поддерживается в данном примере');
      end;
    end;
  finally
    CloseHandle(hProcess);
  end;
end;

end.
