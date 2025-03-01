program Injector;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  MemoryUtils;

var
  Inject: TInject;
  EXE, DLL: ansistring;

begin

  EXE := 'Project1.exe';
  DLL := 'D:\Project\Injector\Debug\Project1.dll';

  Inject := TInject.Create(INJECT_TYPE.APCInjection, EXE, DLL);
  try
    if Inject.InjectDLL then
      WriteLn('DLL injected successfully!')
    else
      WriteLn('Failed to inject DLL.');
  finally
    Inject.Free;
    ReadLn;
  end;

end.
