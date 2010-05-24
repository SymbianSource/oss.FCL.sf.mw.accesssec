::=============================================================================
:: Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
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
::
:: Following commands are implemented:
:: - CLEAN_OLD_FILES
:: - COMPILE_QTCONFIGUTILS
:: - COMPILE_TEST_CASES
:: - RUN_TEST_CASES
:: - GENERATE_REPORTS
:: - SHOW_RESULTS
:: - START_BROWSER
::=============================================================================

::-----------------------------------------------------------------------------
:: Do the preparations:
:: - Don't show the commands
:: - Use local parameters -- don't pollute the global one
::-----------------------------------------------------------------------------
@echo off

::echo *** WST_MAKE: START:
setlocal

::-----------------------------------------------------------------------------
:: Check input
:: 
:: Parameters that are required:
:: 1) wst_root_dir
:: 2) log_file_name
:: 3) the command
::-----------------------------------------------------------------------------

:: (1)
if not exist %1 goto ERROR
if [%1]==[] goto ERROR
set wst_root_dir=%1
set wst_log_dir=%1\wst_log
set qtconfigutils_root_dir=%1\..
set qtconfigutils_test_dir=%1\

:: (2)
if [%2]==[] goto ERROR
set log_file_name=%2
set log_file=%wst_log_dir%\%log_file_name%
if not exist %log_file% goto ERROR
echo *** DATE AND TIME: %date%, %time% >> %log_file%
echo *** WST_MAKE: INFO: qtconfigutils root dir: %qtconfigutils_root_dir%
echo *** WST_MAKE: INFO: qtconfigutils test dir: %qtconfigutils_test_dir%
echo *** WST_MAKE: INFO: WST log dir:            %wst_log_dir%
echo *** WST_MAKE: INFO: WST log file:           %log_file%

:: (3)
if [%3]==[] goto ERROR
goto %3

:: Error if label not found.
goto ERROR

::-----------------------------------------------------------------------------
:CLEAN_OLD_FILES
::-----------------------------------------------------------------------------

echo *** WST_MAKE: CLEAN_OLD_FILES:
echo *** WST_LOG: CLEAN_OLD_FILES >> %log_file%

move %wst_log_dir%\%log_file_name% %wst_root_dir%
del /F /S /Q %wst_log_dir%\*
rmdir /S /Q %wst_log_dir%\CMTHTML
rmdir /S /Q %wst_log_dir%\CTCHTML
move %wst_root_dir%\%log_file_name% %wst_log_dir% 
del \epoc32\winscw\c\data\qtconfigutils_qtext_log.txt

goto THE_END

::-----------------------------------------------------------------------------
:COMPILE_QTCONFIGUTILS
::-----------------------------------------------------------------------------

echo *** WST_MAKE: COMPILE_QTCONFIGUTILS:
echo *** WST_LOG: COMPILE_QTCONFIGUTILS >> %log_file%

cd %qtconfigutils_root_dir%
call qmake "CONFIG += coverage_test debug" >> %log_file% 2>&1
call sbs -c winscw REALLYCLEAN >> %log_file% 2>&1
:: Call CTC instrumentation script. Source directories hard coded, because NO_EXCLUDE does not like % characters...
call ctcwrap -C EXCLUDE=* -C NO_EXCLUDE=.\eapqtconfiginterface\src\*.cpp,.\eapqtplugininfo\src\*.cpp -2comp -n %wst_log_dir%\MON.sym -i d -v sbs -c winscw_udeb >> %log_file% 2>&1


goto THE_END

::-----------------------------------------------------------------------------
:COMPILE_TEST_CASES
::-----------------------------------------------------------------------------

echo *** WST_MAKE: COMPILE_TEST_CASES:
echo *** WST_LOG: COMPILE_TEST_CASES >> %log_file%

cd %qtconfigutils_test_dir%
call qmake "CONFIG += debug include_ui_tests" >> %log_file% 2>&1
call sbs -c winscw REALLYCLEAN >> %log_file% 2>&1
call sbs -c winscw_udeb >> %log_file% 2>&1

goto THE_END

::-----------------------------------------------------------------------------
:RUN_TEST_CASES
::-----------------------------------------------------------------------------

echo *** WST_MAKE: RUN_TEST_CASES:
echo *** WST_LOG: RUN_TEST_CASES >> %log_file%

call \epoc32\release\winscw\udeb\t_qtconfigutils.exe -o c:\data\qtconfigutils_qtext_log.txt

goto THE_END

::-----------------------------------------------------------------------------
:GENERATE_REPORTS
::-----------------------------------------------------------------------------

echo *** WST_MAKE: GENERATE_REPORTS:
echo *** WST_LOG: GENERATE_REPORTS >> %log_file%

cd %wst_log_dir%

call ctcpost -p %wst_log_dir%\ctc_coverage.txt
call ctc2html -nsb -i %wst_log_dir%\ctc_coverage.txt

call dir /s /b %qtconfigutils_root_dir%\*.cpp > %wst_log_dir%\raw_filelist.txt

call findstr /I /V "moc_" %wst_log_dir%\raw_filelist.txt > %wst_log_dir%\filelist.txt
call cmt -f %wst_log_dir%\filelist.txt -o cmt_metrics.txt  >> %log_file%
call cmt2html -nsb -i cmt_metrics.txt

:: Clean up temp files
call del %wst_log_dir%\*filelist.txt

echo *** WST_MAKE: COPY LOGS:
call copy %TEMP%\epocwind.out %wst_log_dir%\epocwind.txt

goto THE_END

::-----------------------------------------------------------------------------
:SHOW_RESULTS
::-----------------------------------------------------------------------------

echo *** WST_MAKE: SHOW_RESULTS:
echo *** WST_LOG: SHOW_RESULTS >> %log_file%
echo *** Module tests:
call findstr /C:"Totals: " \epoc32\winscw\c\data\qtconfigutils_qtext_log.txt
echo *** Coverage:
call findstr /C:"Number of " %wst_log_dir%\ctc_coverage.txt
call findstr /C:"TER       " %wst_log_dir%\ctc_coverage.txt

goto THE_END 

::-----------------------------------------------------------------------------
:START_BROWSER
::-----------------------------------------------------------------------------

echo *** WST_MAKE: START_BROWSER:
echo *** WST_LOG: START_BROWSER >> %log_file%
echo.
echo Starting up browser to show the results

start %wst_log_dir%\coverage.html

goto THE_END

::-----------------------------------------------------------------------------
:ERROR
::-----------------------------------------------------------------------------

echo *** WST_MAKE: ERROR:
endlocal
echo wst_make *** Error (unknown parameter) >> %log_file%

goto THE_END

::-----------------------------------------------------------------------------
:THE_END
::-----------------------------------------------------------------------------
:: echo *** WST_MAKE: END:
