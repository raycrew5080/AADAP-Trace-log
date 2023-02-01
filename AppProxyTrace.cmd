@if "%_echo%"=="" echo off

@rem
@rem Manage AppProxy Release Bits Tracing
@rem
@rem Revision History:
@rem      1.1   Ilan Herbst (ilanh)     24-Oct-2012
@rem      1.2   Arpad Gulyas (arpadg)   25-Nov-2020 

echo AppProxytrace 1.2 - Manage AppProxy Release Bits Tracing.

set AppProxyBinaryLog=%windir%\debug\AppProxylog.bin
set AppProxyTextLog=%windir%\debug\AppProxylog.txt

echo %CD%

@rem
@rem Jump to where we handle usage
@rem
if /I "%1" == "help" goto Usage
if /I "%1" == "-help" goto Usage
if /I "%1" == "/help" goto Usage
if /I "%1" == "-h" goto Usage
if /I "%1" == "/h" goto Usage
if /I "%1" == "-?" goto Usage
if /I "%1" == "/?" goto Usage

@rem
@rem Set TraceFormat environment variable
@rem
if /I "%1" == "-path" shift&goto SetPath
if /I "%1" == "/path" shift&goto SetPath
goto EndSetPath
:SetPath
if /I not "%1" == "" goto DoSetPath
echo ERROR: Argument '-path' specified without argument for TraceFormat folder.
echo Usage example: AppProxyTrace -path x:\sym\TraceFormat
goto :eof
:DoSetPath
echo Setting TRACE_FORMAT_SEARCH_PATH to '%1'
set TRACE_FORMAT_SEARCH_PATH=%1&shift
goto :eof
:EndSetPath

@rem
@rem Format binary log file to text file
@rem
if /I "%1" == "-format" shift&goto FormatFile
if /I "%1" == "/format" shift&goto FormatFile
goto EndFormatFile
:FormatFile
if /I not "%TRACE_FORMAT_SEARCH_PATH%" == "" goto DoFormatFile
echo ERROR: Argument '-format' specified without running 'AppProxyTrace -path' first.
echo Usage example: AppProxyTrace -path x:\sym\TraceFormat
echo                AppProxyTrace -format ('%AppProxyBinaryLog%' to text file '%AppProxyTextLog%')
goto :eof
:DoFormatFile
set AppProxyBinaryLog=%windir%\debug\AppProxylog.bin
if /I not "%1" == "" set AppProxyBinaryLog=%1&shift
echo Flushing AppProxy trace...
call tracelog -flush AppProxy
echo Formatting binary log file '%AppProxyBinaryLog%' to '%AppProxyTextLog%'.
call tracefmt %AppProxyBinaryLog% -o %AppProxyTextLog%
set AppProxyBinaryLog=
goto :eof
:EndFormatFile



@rem
@rem Process the tracing change
@rem
if /I "%1" == "-change" shift&goto ChangeTrace
if /I "%1" == "/change" shift&goto ChangeTrace
goto EndChangeTrace
:ChangeTrace
@rem
@rem Process the module
@rem
set ModuleGuid=
if /I "%1" == "INFRA"        set ModuleGuid="6519B1CA-2DD1-45D8-A53A-34D03B24EF58"
if /I "%1" == "CORE"        set ModuleGuid="2C7484EA-F1AC-4A4F-8FF0-39222A187F0D"
if /I "%1" == "CONFIG"        set ModuleGuid="DBD9121B-9FC9-4725-B35D-EC411FC28196"
if /I "%1" == "HANDLER"        set ModuleGuid="7B879E0C-83A7-4DCA-8492-063A257D4288"
if /I "%1" == "PSPROVIDER"	set ModuleGuid="66C13383-C691-4CF7-B404-7E172E2DC0C2"

shift
if /I "%ModuleGuid%" == "" goto Usage

@rem
@rem Process the level (error = 0x1, warning = 0x2, info = 0x4, func = 0x8, noise = 0x10)
@rem
set TraceLevel=
if /I "%1" == "none" set TraceLevel=0x0
if /I "%1" == "error" set TraceLevel=0x1
if /I "%1" == "warning" set TraceLevel=0x3
if /I "%1" == "info" set TraceLevel=0x7
if /I "%1" == "func" set TraceLevel=0xf
if /I "%1" == "func_error" set TraceLevel=0x9
if /I "%1" == "noise" set TraceLevel=0x1F
shift
if /I "%TraceLevel%" == "" goto Usage

@rem
@rem Query if AppProxy logger is running. If not, echo and exit
@rem
:QueryLoggerRunning
echo Querying if AppProxy logger is currently running...
call tracelog -q AppProxy
if ERRORLEVEL 1 goto LoggerNotRunning
echo AppProxy logger is currently running, changing trace level...
goto EndQueryLogger


:LoggerNotRunning
echo.
echo.
echo AppProxy logger is not currently running
echo Please invoke AppProxyTrace to start tracing
goto :eof


:EndQueryLogger
@rem
@rem At this point if we have any argument it's an error
@rem
if /I not "%1" == "" goto Usage


@rem
@rem Make the change
@rem
call tracelog -enable AppProxy -flags %TraceLevel% -guid #%ModuleGuid%

goto :eof
:EndChangeTrace


@rem
@rem Consume the -rt argument
@rem
set AppProxyRealTime=
if /I "%1" == "-rt" shift&goto ConsumeRealTimeArgument
if /I "%1" == "/rt" shift&goto ConsumeRealTimeArgument
goto EndConsumeRealTimeArgument
:ConsumeRealTimeArgument
if /I not "%TRACE_FORMAT_SEARCH_PATH%" == "" goto DoConsumeRealTimeArgument
echo ERROR: Argument '-rt' specified without running 'AppProxyTrace -path' first.
echo Usage example: AppProxyTrace -path x:\sym\TraceFormat
echo                AppProxyTrace -rt (start RealTime logging/formatting at Error level)
goto :eof
:DoConsumeRealTimeArgument
echo Running AppProxy trace in Real Time mode...
set AppProxyRealTime=-rt -ft 1
:EndConsumeRealTimeArgument

@rem
@rem Handle the -stop argument
@rem
if /I "%1" == "-stop" shift&goto HandleStopArgument
if /I "%1" == "/stop" shift&goto HandleStopArgument
goto EndHandleStopArgument
:HandleStopArgument
echo Flushing AppProxy trace...
call tracelog -flush AppProxy
echo Stopping AppProxy trace...
call tracelog -stop AppProxy
goto :eof
:EndHandleStopArgument

@rem
@rem Consume the "-start" argument if it exists. Default is to start.
@rem
echo Starting AppProxy trace logging to '%AppProxyBinaryLog%'...
if /I "%1" == "-start" shift&goto starttrace
if /I "%1" == "/start" shift&goto starttrace

@rem
@rem Process the tracing update
@rem
if /I "%1" == "-update" shift&goto UpdateTrace
if /I "%1" == "/update" shift&goto UpdateTrace


:starttrace
set AppProxyBinaryLog=%windir%\debug\AppProxylog.bin
goto EndHandleArgument1

:UpdateTrace
set AppProxyBinaryLog=
set AppProxyOpenLogger=
set AppProxyStartLogger=-update

@rem
@rem Consume the -rt argument
@rem
set AppProxyRealTime=
if /I "%1" == "-rt" shift&goto ConsumeRealTimeArgument1
if /I "%1" == "/rt" shift&goto ConsumeRealTimeArgument1
goto EndHandleArgument1
:ConsumeRealTimeArgument1
if /I not "%TRACE_FORMAT_SEARCH_PATH%" == "" goto DoConsumeRealTimeArgument1
echo ERROR: Argument '-rt' specified without running 'AppProxyTrace -path' first.
echo Usage example: AppProxyTrace -path x:\sym\TraceFormat
echo                AppProxyTrace -update -rt (start RealTime logging/formatting at Error level)
goto :eof
:DoConsumeRealTimeArgument1
echo Running AppProxy trace in Real Time mode...
set AppProxyRealTime=-rt -ft 1
:EndConsumeRealTimeArgument
goto EndHandleArgument1

:EndHandleArgument1

@rem
@rem Process the noise level argument if it exists. Default is error level.
@rem

if /I "%1" == "-noise" set AppProxyFlags=0x1f & echo AppProxy trace noise level is NOISE... & shift & goto EndHandleLevel
if /I "%1" == "/noise" set AppProxyFlags=0x1f & echo AppProxy trace noise level is NOISE... & shift & goto EndHandleLevel

if /I "%1" == "-func"  set AppProxyFlags=0xf & echo AppProxy trace noise level is FUNC... & shift & goto EndHandleLevel
if /I "%1" == "/func"  set AppProxyFlags=0xf & echo AppProxy trace noise level is FUNC... & shift & goto EndHandleLevel

if /I "%1" == "-func_error" set AppProxyFlags=0x9 & echo AppProxy trace noise level is FUNC_ERROR... & shift & goto EndHandleLevel
if /I "%1" == "/func_error" set AppProxyFlags=0x9 & echo AppProxy trace noise level is FUNC_ERROR... & shift & goto EndHandleLevel

if /I "%1" == "-info" set AppProxyFlags=0x7 & echo AppProxy trace noise level is INFO... & shift & goto EndHandleLevel
if /I "%1" == "/info" set AppProxyFlags=0x7 & echo AppProxy trace noise level is INFO... & shift & goto EndHandleLevel

if /I "%1" == "-warning" set AppProxyFlags=0x3 & echo AppProxy trace noise level is WARNING... & shift & goto EndHandleLevel
if /I "%1" == "/warning" set AppProxyFlags=0x3 & echo AppProxy trace noise level is WARNING... & shift & goto EndHandleLevel

if /I "%1" == "-error" set AppProxyFlags=0x1 & echo AppProxy trace noise level is ERROR... & shift & goto EndHandleLevel
if /I "%1" == "/error" set AppProxyFlags=0x1 & echo AppProxy trace noise level is ERROR... & shift & goto EndHandleLevel

set AppProxyFlags=0x1
echo AppProxy trace noise level is ERROR...
:EndHandleLevel


@rem
@rem Handle the -cir argument
@rem
if /I "%1" == "-cir" shift&goto HandleCirArgument
if /I "%1" == "/cir" shift&goto HandleCirArgument
set LogFileSettings= -cir 400
goto EndHandleCirArgument
:HandleCirArgument
if not "%1" == "" goto SetLogSize
echo ERROR: Argument '-cir' specified without running providing size.
echo Usage example: AppProxyTrace -start -error -cir 300
goto :eof
:SetLogSize
set LogFileSettings= -cir %1
shift&goto EndHandleCirArgument
:EndHandleCirArgument


@rem
@rem At this point if we have any argument it's an error
@rem
if /I not "%1" == "" goto Usage

@rem
@rem Query if AppProxy logger is running. If so only update the flags and append to logfile.
@rem
echo Querying if AppProxy logger is currently running...
call tracelog -q AppProxy
if ERRORLEVEL 1 goto LoggerNotRunning
echo AppProxy logger is currently running, appending new trace output...

if NOT defined AppProxyBinaryLog goto EndQueryLogger1

set AppProxyStartLogger=-enable
set AppProxyOpenLogger=-append
goto EndQueryLogger1
:LoggerNotRunning
echo AppProxy logger is not currently running, starting new logger...
set AppProxyStartLogger=-start
set AppProxyOpenLogger=-f
:EndQueryLogger1

@rem
@rem Start a new AppProxy logger or update the existing one
@rem
if defined AppProxyBinaryLog goto NormalStart

set AppProxyDefaultLogParam=-f %systemdrive%\LogFile.etl
call tracelog %AppProxyStartLogger% AppProxy %AppProxyRealTime% %LogFileSettings% %AppProxyDefaultLogParam%
call tracelog -enable AppProxy -flags %AppProxyFlags% -guid #40b68c42-5d07-4703-8797-329c4b04ad3f & @rem GENERAL
goto NormalContinue

:NormalStart
call tracelog %AppProxyStartLogger% AppProxy %AppProxyRealTime% %LogFileSettings% -flags %AppProxyFlags% %AppProxyOpenLogger% %AppProxyBinaryLog% -guid #40b68c42-5d07-4703-8797-329c4b04ad3f & @rem GENERAL
goto NormalContinue

:NormalContinue
call tracelog -enable AppProxy -flags %AppProxyFlags% -guid #6519B1CA-2DD1-45D8-A53A-34D03B24EF58 & @rem INFRA
call tracelog -enable AppProxy -flags %AppProxyFlags% -guid #2C7484EA-F1AC-4A4F-8FF0-39222A187F0D & @rem CORE
call tracelog -enable AppProxy -flags %AppProxyFlags% -guid #DBD9121B-9FC9-4725-B35D-EC411FC28196 & @rem CONFIG
call tracelog -enable AppProxy -flags %AppProxyFlags% -guid #7B879E0C-83A7-4DCA-8492-063A257D4288 & @rem HANDLER
call tracelog -enable AppProxy -flags %AppProxyFlags% -guid #66C13383-C691-4CF7-B404-7E172E2DC0C2 & @rem PSPROVIDER

set AppProxyFlags=
set AppProxyStartLogger=
set AppProxyOpenLogger=

@rem
@rem In real time mode, start formatting
@rem
if /I "%AppProxyRealTime%" == "" goto EndRealTimeFormat
echo Starting AppProxy real time formatting...
if defined AppProxyBinaryLog goto NormalRealTimeStart
logman update AppProxy -rt -ets
:NormalRealTimeStart
call tracefmt -display -rt AppProxy -o %AppProxyTextLog%
:EndRealTimeFormat
set AppProxyRealTime=
goto :eof

:Usage
echo.
echo Usage: AppProxyTrace [^<Action^>] [^<Level^>]
echo        AppProxyTrace -?
echo.
echo Advance Usage: AppProxyTrace -path ^<TraceFormat folder^>
echo                AppProxyTrace -rt [^<Action^>] [^<Level^>]
echo                AppProxyTrace -format [^<Binary log file^>]
echo                AppProxyTrace -change ^<Module^> ^<Level^>
echo                AppProxyTrace -update [-rt] ^<Level^>
echo.
echo ^<Action^> - Optional trace action:
echo     -start   - start/update trace logging to '%AppProxyBinaryLog%' (default).
echo     -stop    - stop trace logging.
echo.
echo ^<Level^>  - Optional trace level (overrides current trace level):
echo     -error   - trace error messages only (default).
echo     -warning - trace warning and error messages.
echo     -info    - trace information, warning and error messages.
echo     -func    - trace func entry/exit, information, warning and error messages.
echo     -func_error - trace func entry/exit, error messages.
echo     -noise   - trace noise, func, information, warning and error messages.
echo.
echo -?      - Display this usage message.
echo.
echo -path   - Set environment variable for TraceFormat folder.
echo           This variable is necessary for later use of -rt or -format
echo           and needs to be set once (per command-line box).
echo.
echo -rt     - Start trace logger and formatter in Real Time mode.
echo           Environment variable must be set first, see '-path'.
echo           In addition, binary log is kept in '%AppProxyBinaryLog%'.
echo.
echo -format - Format binary log file to text file '%AppProxyTextLog%'.
echo           Environment variable must be set first, see '-path'.
echo.
echo -change - Change the trace level for each module
echo.
echo -update - Update the trace level for all modules
echo.
echo -cir n  - start only argument: set circular log size to size n
echo.
echo ^<Binary log file^> - Optional binary log file. Default is '%AppProxyBinaryLog%'.
echo.
echo ^<Module^>: The module for which to change the debug level
echo     modules are:
echo        INFRA, CORE, CONFIG, HANDLER, PSPROVIDER
echo.
echo ^<Level^>  - Trace level (overrides current trace level):
echo     none    - shut down debug from this module
echo     error   - trace error messages only (default).
echo     warning - trace warning and error messages.
echo     info    - trace information, warning and error messages.
echo     func    - trace func entry/exit, information, warning and error messages.
echo     func_error - trace func entry/exit, error messages.
echo     noise    - trace noise, func, information, warning and error messages.
echo.
echo.
echo Example 1: AppProxyTrace (start/update logging to '%AppProxyBinaryLog%' at Error level)
echo Example 2: AppProxyTrace -path x:\Sym\TraceFormat
echo Example 3: AppProxyTrace -rt -info (start real time logging at Info level)
echo Example 4: AppProxyTrace -change INFRA warning
echo Example 5: AppProxyTrace -update -rt -info
echo Example 6: AppProxyTrace -format (format '%AppProxyBinaryLog%' to '%AppProxyTextLog%')
echo Example 7: AppProxyTrace -stop (stop logging)

