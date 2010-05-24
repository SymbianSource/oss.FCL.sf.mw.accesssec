::=============================================================================
:: Copyright (c) 2009 Nokia Corporation and/or its subsidiary(-ies).
:: All rights reserved.
:: This component and the accompanying materials are made available
:: under the terms of "Eclipse Public License v1.0"
:: which accompanies this distribution, and is available
:: at the URL "http://www.eclipse.org/legal/epl-v10.html".
::
:: Initial Contributors:
:: Nokia Corporation - initial contribution.
::
:: Contributors:
::
:: Description:
::
::=============================================================================

:: Script(s) uses following environment settings:
:: - CD
:: - DATE
:: - TIME
:: - TEMP


::-----------------------------------------------------------------------------
:: Do the preparations:
:: - Don't show the commands
:: - Use local parameters -- don't pollute the global one
:: - Dim the lights for time of script execution
:: - Store the current working directory
::-----------------------------------------------------------------------------

@echo off
:: echo *** RUN_WST: START:
setlocal
color 08
pushd .
if not exist run_wst.bat goto INVALID_DIR


::-----------------------------------------------------------------------------
:: Set the local variables
::-----------------------------------------------------------------------------

::echo *** RUN_WST: SET VARIABLES:
set wst_root_dir=%cd%
set wst_log_dir=%wst_root_dir%\wst_log
set log_file=%wst_log_dir%\wst_log.txt
set build_script=%wst_root_dir%\wst_script\wst_make.bat

::-----------------------------------------------------------------------------
:: Check that script exists
::-----------------------------------------------------------------------------

::echo *** RUN_WST: SOME CHECKS:
if not exist %build_script% goto INVALID_DIR
:: Create output directory if it does not exist
if not exist %wst_log_dir% mkdir %wst_log_dir%
:: Create log file
echo *** WST_LOG: BEGIN *** > %log_file%


::-----------------------------------------------------------------------------
:: Check parameters
::-----------------------------------------------------------------------------

set command=ERROR
if [%1]==[] set command=CLEAN_OLD_FILES COMPILE_QTCONFIGUTILS COMPILE_TEST_CASES RUN_TEST_CASES GENERATE_REPORTS SHOW_RESULTS
if [%1]==[CLEAN_OLD] set command=CLEAN_OLD_FILES
if [%1]==[COMPILE] set command=COMPILE_QTCONFIGUTILS
if [%1]==[CASES] set command=COMPILE_TEST_CASES
if [%1]==[RUN] set command=RUN_TEST_CASES
if [%1]==[REPORTS] set command=GENERATE_REPORTS
if [%1]==[RESULTS] set command=SHOW_RESULTS
if [%1]==[BROWSE] set command=START_BROWSER
if [%1]==[/?] goto HELP
if [%1]==[HELP] goto HELP
if [%1]==[/h] goto HELP
if [%1]==[-h] goto HELP

::-----------------------------------------------------------------------------
:PARSE_COMMANDS
::-----------------------------------------------------------------------------

:: echo *** RUN_WST: COMMAND: %command%
:: echo *** RUN_WST: CALL SCRIPT:
for %%i IN ( %command% ) DO (
    call %build_script% %wst_root_dir% wst_log.txt %%i
    for /f "tokens=3 delims= " %%x in ('find /C " Error " %log_file%') do (
        if not [%%x]==[0] goto ERROR
    )
)

goto THE_END


::-----------------------------------------------------------------------------
:INVALID_DIR
::-----------------------------------------------------------------------------

echo *** RUN_WST: INVALID DIR:
echo *** Test script sub-script not found!
echo *** Please be sure to run the script in same directory,
echo *** i.e. .\run_wst.bat , and NOT .\wst\run_wst.bat

goto THE_END


::-----------------------------------------------------------------------------
:ERROR
::-----------------------------------------------------------------------------

echo *** RUN_WST: ERROR:
color 48
echo Error in compilation:
findstr /C:" Error " < %log_file%
echo.
Echo Quitting WST.

goto THE_END


::-----------------------------------------------------------------------------
:HELP
::-----------------------------------------------------------------------------

echo *** RUN_WST: HELP:
echo Run EAP Qt Configuration Utilities Workstation Testing
echo.
echo RUN_WST [param]
echo.
echo   param
echo     [none]  - Do all, from CLEAN_OLD to RESULTS
echo.
echo     CLEAN_OLD - Clean metrics and other generated files
echo     COMPILE - Build EAP QT configuration utilities (qtconfigutils)
echo     CASES   - Build only Tester components
echo     RUN     - Run Tester
echo     REPORTS - Generate reports
echo     RESULTS - Show results
echo     BROWSE  - Start browser
echo.


::-----------------------------------------------------------------------------
:THE_END
::-----------------------------------------------------------------------------

echo *** RUN_WST: Completed:
color
popd
