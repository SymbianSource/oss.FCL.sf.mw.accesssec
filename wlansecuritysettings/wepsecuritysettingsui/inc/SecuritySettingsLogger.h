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
* Description: Logger utility.
*
*/

/*
* %version: tr1cfwln#8 %
*/

#ifndef SECURITYSETTINGSLOGGER_H
#define SECURITYSETTINGSLOGGER_H


// INCLUDES

#include <e32std.h>
#include <e32def.h>
#include <flogger.h>


#ifdef _DEBUG
#define __SEC_SETT_LOG__
#endif // _DEBUG


#ifdef __SEC_SETT_LOG__

// CONSTANTS

// SecuritySettingsLogger logging directory.
_LIT( KSecSettLogDir,                   "TestSecSett" );
// SecSett log file name.
_LIT( KSecSettLogFile,                  "SecSett.log" );
// Format string: enter function.
_LIT( KSecSettLogEnterFn,               "-> %S" );
// Format string: leave function.
_LIT( KSecSettLogLeaveFn,               "<- %S" );
// Format string: time.
_LIT( KSecSettLogTimeFormatString,      "%H:%T:%S:%*C2" );
// Format string: timestamp.
_LIT( KSecSettLogTimeStampFormatString, "%S %S" );

// DEFINES

// Write log: enter function.
#define CLOG_ENTERFN( a )           \
    {                               \
    _LIT( temp, a );                \
    RFileLogger::WriteFormat        \
        (                           \
        KSecSettLogDir,             \
        KSecSettLogFile,            \
        EFileLoggingModeAppend,     \
        KSecSettLogEnterFn,         \
        &temp                       \
        );                          \
    }

// Write log: leave function.
#define CLOG_LEAVEFN( a )           \
    {                               \
    _LIT( temp, a );                \
    RFileLogger::WriteFormat        \
        (                           \
        KSecSettLogDir,             \
        KSecSettLogFile,            \
        EFileLoggingModeAppend,     \
        KSecSettLogLeaveFn,         \
        &temp                       \
        );                          \
    }

// Write log: string 'a'.
#define CLOG_WRITE( a )             \
    {                               \
    _LIT( temp, a );                \
    RFileLogger::Write              \
        (                           \
        KSecSettLogDir,             \
        KSecSettLogFile,            \
        EFileLoggingModeAppend,     \
        temp                        \
        );                          \
    }

// Write log: formatted.
#define CLOG_WRITE_FORMAT( a, b )   \
    {                               \
    _LIT( temp, a );                \
    RFileLogger::WriteFormat        \
        (                           \
        KSecSettLogDir,             \
        KSecSettLogFile,            \
        EFileLoggingModeAppend,     \
        temp,                       \
        b                           \
        );                          \
    }

// Write log: timestamp.
#define CLOG_WRITE_TIMESTAMP( a )                                   \
    {                                                               \
    _LIT( temp, a );                                                \
    TTime time;                                                     \
    time.HomeTime();                                                \
    TBuf<32> timeBuf;                                               \
    TRAPD( err, time.FormatL( timeBuf, KSecSettLogTimeFormatString ) ); \
    if ( !err )                                                     \
        {                                                           \
        RFileLogger::WriteFormat                                    \
            (                                                       \
            KSecSettLogDir,                                         \
            KSecSettLogFile,                                        \
            EFileLoggingModeAppend,                                 \
            KSecSettLogTimeStampFormatString,                       \
            &temp,                                                  \
            &timeBuf                                                \
            );                                                      \
        }                                                           \
    }

#else // not defined __SEC_SETT_LOG__

// DEFINES

// Empty definition (disable log).
#define CLOG_ENTERFN( a )

// Empty definition (disable log).
#define CLOG_LEAVEFN( a )

// Empty definition (disable log).
#define CLOG_WRITE( a )

// Empty definition (disable log).
#define CLOG_WRITE_FORMAT( a, b )

// Empty definition (disable log).
#define CLOG_WRITE_TIMESTAMP( a )

#endif // __SEC_SETT_LOG__

#endif 
