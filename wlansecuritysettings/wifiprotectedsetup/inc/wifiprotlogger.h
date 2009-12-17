/*
* Copyright (c) 2001-2009 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of the License "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description: Definition of macros used for logging 
*
*/


#ifndef WIFIPROTLOGGER_H_INCLUDED
#define WIFIPROTLOGGER_H_INCLUDED

// ========== INCLUDE FILES ================================

#include <eikenv.h>
#include <flogger.h>

#ifdef _DEBUG

// Format string: enter function.
_LIT( KCCDLGLogEnterFn,           "-> %S" );
// Format string: leave function.
_LIT( KCCDLGLogLeaveFn,           "<- %S" );
// Format string: time.
_LIT( KCCDLGLogTimeFormatString,  "%H:%T:%S:%*C2" );

// Logging directory.
_LIT( KCCDLGLogDir,               "wps" );
// Log file name.
_LIT( KCCDLGLogFile,              "wps.txt" );
_LIT( KCCDLGLogBanner,            "****************\n\nWiFiProtectedSetupUi\n\n****************" );
_LIT( KCCDLGLogExit,              "WiFiProtectedSetupUi: Exit" );

#define CLOG_CREATE             {FCreate();}
#define CLOG_DELETE             {RFileLogger::Write(KCCDLGLogDir, KCCDLGLogFile, EFileLoggingModeAppend, KCCDLGLogExit);}
#define CLOG_ENTERFN(a)         {_LIT(temp, a); RFileLogger::WriteFormat(KCCDLGLogDir, KCCDLGLogFile, EFileLoggingModeAppend, KCCDLGLogEnterFn, &temp);}
#define CLOG_LEAVEFN(a)         {_LIT(temp, a); RFileLogger::WriteFormat(KCCDLGLogDir, KCCDLGLogFile, EFileLoggingModeAppend, KCCDLGLogLeaveFn, &temp);}
#define CLOG_WRITE(a)           {_LIT(temp, a); RFileLogger::Write(KCCDLGLogDir, KCCDLGLogFile, EFileLoggingModeAppend, temp);}
#define CLOG_WRITE_TIMESTAMP(a) {_LIT(temp, a); TTime time; time.HomeTime(); TBuf<256> buffer; time.FormatL( buffer, KCCDLGLogTimeFormatString ); buffer.Insert(0, temp); RFileLogger::Write(KCCDLGLogDir, KCCDLGLogFile, EFileLoggingModeAppend, buffer); }
#define CLOG_WRITEF             FPrint

// ---------------------------------------------------------
// FPrint
// ---------------------------------------------------------
//
inline void FPrint(const TRefByValue<const TDesC> aFmt, ...)
    {
    VA_LIST list;
    VA_START(list,aFmt);
    RFileLogger::WriteFormat(KCCDLGLogDir, KCCDLGLogFile, EFileLoggingModeAppend, aFmt, list);
    }

// ---------------------------------------------------------
// FPrint
// ---------------------------------------------------------
//
inline void FPrint(const TDesC& aDes)
    {
    RFileLogger::WriteFormat(KCCDLGLogDir, KCCDLGLogFile, EFileLoggingModeAppend, aDes);
    }

// ---------------------------------------------------------
// FHex
// ---------------------------------------------------------
//
inline void FHex(const TUint8* aPtr, TInt aLen)
    {
    RFileLogger::HexDump(KCCDLGLogDir, KCCDLGLogFile, EFileLoggingModeAppend, 0, 0, aPtr, aLen);
    }

// ---------------------------------------------------------
// FHex
// ---------------------------------------------------------
//
inline void FHex(const TDesC8& aDes)
    {
    FHex(aDes.Ptr(), aDes.Length());
    }

// ---------------------------------------------------------
// FCreate
// ---------------------------------------------------------
//
inline void FCreate()
    {
    TFileName path( _L( "c:\\logs\\" ) );
    path.Append( KCCDLGLogDir );
    path.Append( _L( "\\" ) );
    RFs& fs = CEikonEnv::Static()->FsSession();
    fs.MkDirAll( path );
    RFileLogger::WriteFormat( KCCDLGLogDir, KCCDLGLogFile, 
                              EFileLoggingModeAppend, KCCDLGLogBanner );
    }

#else // ! _DEBUG

// ---------------------------------------------------------
// FPrint
// ---------------------------------------------------------
//
inline void FPrint(const TRefByValue<const TDesC> /*aFmt*/, ...) { };

#define CLOG_CREATE
#define CLOG_DELETE
#define CLOG_ENTERFN(a)
#define CLOG_LEAVEFN(a)
#define CLOG_WRITE(a)
#define CLOG_WRITEF   1 ? ((void)0) : FPrint
#define CLOG_WRITE_TIMESTAMP(a)

#endif // _DEBUG


#endif // WIFIPROTLOGGER_H_INCLUDED
