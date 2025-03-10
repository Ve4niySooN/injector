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
    WDllPath: WideString;
    WDllName: WideString;
    FInjectType: INJECT_TYPE;
    function GetProcessID(ProcessName: string): DWORD;
    function IsModuleLoaded(ModulePath: ansistring; ProcessID: DWORD): Boolean;
  public
    constructor Create(InjectType: INJECT_TYPE; ProcessName, DLLPath: ansistring);
    function InjectDLL: Boolean;
  end;

implementation

function OpenThread(
  dwDesiredAccess: DWORD;
  bInheritHandle: BOOL;
  dwThreadId: DWORD): THandle; stdcall; external 'kernel32.dll';

function NtQueryInformationThread(
  ThreadHandle: THandle;
  ThreadInformationClass: DWORD;
  ThreadInformation: Pointer;
  ThreadInformationLength: ULONG;
  ReturnLength: PULONG): NTSTATUS; stdcall; external 'ntdll.dll';

var
  {$IFDEF CPUX64}
    LdrLoadDll_Shell: array[0..32] of Byte = (
      $48, $83, $EC, $28,     // sub rsp, 28h
      $48, $8B, $01,          // mov rax, [rcx]
      $4C, $8B, $51, $08,     // mov r10, [rcx+8]
      $48, $8B, $51, $10,     // mov rdx, [rcx+10h]
      $4C, $8B, $41, $18,     // mov r8,  [rcx+18h]
      $4C, $8B, $49, $20,     // mov r9,  [rcx+20h]
      $4C, $89, $D1,          // mov rcx, r10
      $FF, $D0,               // call rax
      $48, $83, $C4, $28,     // add rsp, 28h
      $C3                     // ret
    );
  {$ELSE}
    LdrLoadDll_Shell: array[0..23] of Byte = (
      $55,                    // push ebp
      $89, $E5,               // mov ebp, esp
      $8B, $55, $08,          // mov edx, [ebp+8]
      $FF, $72, $10,          // push [edx+10h]
      $FF, $72, $0C,          // push [edx+0Ch]
      $FF, $72, $08,          // push [edx+08h]
      $FF, $72, $04,          // push [edx+04h]
      $FF, $12,               // call [edx]
      $C9,                    // leave
      $C2, $04, $00           // ret 4
    );
  {$ENDIF}

type
  THREAD_BASIC_INFORMATION = record
    ExitStatus: NTSTATUS;
    TebBaseAddress: Pointer;
    ClientId: record
      UniqueProcess: ULONG_PTR;
      UniqueThread: ULONG_PTR;
    end;
    AffinityMask: ULONG_PTR;
    Priority: LONG;
    BasePriority: LONG;
  end;

  UNICODE_STRING = record
    Length: USHORT;
    MaximumLength: USHORT;
    Buffer: PWideChar;
  end;
  PUNICODE_STRING = ^UNICODE_STRING;

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

  TLdrLoadDll = function(
    DllPath: PWideChar;
    DllCharacteristics: PULONG;
    DllName: PUNICODE_STRING;
    out DllHandle: Pointer): NTSTATUS; stdcall;

  TLdrLoadDll_Wrapper = record
    LdrLoadDllAddr,
    DLLPath,
    DllCharacteristics,
    DllName,
    DllHandle: UInt;
  end;

const
  THREAD_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED or SYNCHRONIZE or $3FF;

constructor TInject.Create(InjectType: INJECT_TYPE; ProcessName, DLLPath: ansistring);
begin
  FInjectType := InjectType;
  FProcessID  := GetProcessID(string(ProcessName));
  FDLLPath    := DLLPath;
  WDLLPath    := ExtractFilePath(WideString(DLLPath));
  WDLLName    := ExtractFileName(WideString(DLLPath));
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
  pRemoteMemory, pRemoteCode, pLoadLibrary, pLdrLoadDll: Pointer;
  BytesWritten: SIZE_T;
  NtCreateThreadEx: TNtCreateThreadEx;

  // LdrLoad:
  WUNICODE_STRING: UNICODE_STRING;
  PWDllPath: Pointer;
  PWDllName: Pointer;
  PWDLLHandle: Pointer;
  PWUNICODE_STRING: Pointer;
  Wrapper: TLdrLoadDll_Wrapper;
  PLdrLoadDll_Shell: Pointer;
  PLdrLoadDll_Params: Pointer;

  // APC:
  Snapshot: THandle;
  ThreadEntry: TThreadEntry32;
  ThreadInfo: THREAD_BASIC_INFORMATION;
  ThreadAlertable: Byte;
  Status: NTSTATUS;
  ReturnLength: ULONG;
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

          hThread := NtCreateThreadEx(@hThread, MAXIMUM_ALLOWED, nil, hProcess, pLoadLibrary, pRemoteMemory, false, 0, nil, nil, nil);

          // Если используется CreateRemoteThread то возвращается дескриптор потока
          // Если используется NtCreateThreadEx возвращается статус выполнения
          Result  := hThread = 0;

          // Если использовался CreateRemoteThread мы можем закрыть поток после его выполнения
          {
          WaitForSingleObject(hThread, INFINITE);
          CloseHandle(hThread);
          }

        finally
          VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        end;
      end;

      LdrLoadDll:
      begin
        // Для инжекта во всем лучше, чем LoadLibrary, но требует указания полного пути к .dll файлу
        // Для передачи параметров в NtCreateThreadEx используется шелл LdrLoadDll_Shell (x86\x64)

        pLdrLoadDll := GetProcAddress(GetModuleHandle('ntdll.dll'), 'LdrLoadDll');
        if not Assigned(pLdrLoadDll) then Exit;

        PWDllPath := VirtualAllocEx(hProcess, nil, Length(WDllPath) * SizeOf(WCHAR) + 1, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if not Assigned(PWDllPath) then Exit;
        try
          if not WriteProcessMemory(hProcess, PWDllPath, PWideChar(WDllPath), Length(WDllPath) * SizeOf(WCHAR), BytesWritten) then Exit;

          PWDllName := VirtualAllocEx(hProcess, nil, Length(WDllName) * SizeOf(WCHAR) + 1, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
          if not Assigned(PWDllName) then Exit;
          try
            if not WriteProcessMemory(hProcess, PWDllName, PWideChar(WDllName), Length(WDllName) * SizeOf(WCHAR), BytesWritten) then Exit;

            WUNICODE_STRING.Length        := Length(WDllName) * SizeOf(WCHAR);
            WUNICODE_STRING.MaximumLength := WUNICODE_STRING.Length + 2;
            WUNICODE_STRING.Buffer        := PWDllName;

            PWUNICODE_STRING := VirtualAllocEx(hProcess, nil, SizeOf(UNICODE_STRING), MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if not Assigned(PWUNICODE_STRING) then Exit;
            try
              if not WriteProcessMemory(hProcess, PWUNICODE_STRING, @WUNICODE_STRING, SizeOf(UNICODE_STRING), BytesWritten) then Exit;

              PWDLLHandle := VirtualAllocEx(hProcess, nil, SizeOf(HMODULE), MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
              if not Assigned(PWDLLHandle) then Exit;
              try
                Wrapper.LdrLoadDllAddr     := UInt(pLdrLoadDll);
                Wrapper.DLLPath            := UInt(PWDllPath);
                Wrapper.DllCharacteristics := UInt(nil);
                Wrapper.DllName            := UInt(PWUNICODE_STRING);
                Wrapper.DllHandle          := UInt(PWDLLHandle);

                PLdrLoadDll_Params := VirtualAllocEx(hProcess, nil, SizeOf(TLdrLoadDll_Wrapper), MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if not Assigned(PLdrLoadDll_Params) then Exit;
                try
                  if not WriteProcessMemory(hProcess, PLdrLoadDll_Params, @Wrapper, SizeOf(TLdrLoadDll_Wrapper), BytesWritten) then Exit;

                  PLdrLoadDll_Shell := VirtualAllocEx(hProcess, nil, SizeOf(LdrLoadDll_Shell), MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                  if not Assigned(PLdrLoadDll_Shell) then Exit;
                  try
                    if not WriteProcessMemory(hProcess, PLdrLoadDll_Shell, @LdrLoadDll_Shell, SizeOf(LdrLoadDll_Shell), BytesWritten) then Exit;

                    try
                      hThread := NtCreateThreadEx(@hThread, MAXIMUM_ALLOWED, nil, hProcess, PLdrLoadDll_Shell, PLdrLoadDll_Params, false, 0, nil, nil, nil);
                      if hThread <> 0 then Exit;
                    finally
                      Result := True;
                    end;
                  finally
                    VirtualFreeEx(hProcess, PLdrLoadDll_Shell, 0, MEM_RELEASE);
                  end;
                finally
                  VirtualFreeEx(hProcess, PLdrLoadDll_Params, 0, MEM_RELEASE);
                end;
              finally
                VirtualFreeEx(hProcess, PWDLLHandle, 0, MEM_RELEASE);
              end;
            finally
              VirtualFreeEx(hProcess, PWUNICODE_STRING, 0, MEM_RELEASE);
            end;
          finally
            VirtualFreeEx(hProcess, PWDllName, 0, MEM_RELEASE);
          end;
        finally
          VirtualFreeEx(hProcess, PWDllPath, 0, MEM_RELEASE);
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
                    Sleep(100);

                    if IsModuleLoaded(FDLLPath, FProcessID) then
                    begin
                      Result := True;
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