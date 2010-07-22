/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  scheduler of EAP-server.
*
*/

/*
* %version: %
*/

/**
 @file
*/

#include <e32std.h>
#include "EapServerBackup.h"
#include <connect/sbdefs.h>
#include "EapTraceSymbian.h"

using namespace conn;

//----------------------------------------------------------------------------

CEapserverBackup* CEapserverBackup::NewL(AbsEapserverBackup * const aBackupAndRestoreObserver)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapserverBackup::NewL()")));
    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapserverBackup::NewL()\n"));

	CEapserverBackup* self = new(ELeave) CEapserverBackup(aBackupAndRestoreObserver);
	CleanupStack::PushL(self);
	self->ConstructL();
	CleanupStack::Pop(self);
	return self;
}

//----------------------------------------------------------------------------

CEapserverBackup::CEapserverBackup(AbsEapserverBackup * const aBackupAndRestoreObserver)
:CActive(EPriorityStandard)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapserverBackup::CEapserverBackup()")));
    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapserverBackup::CEapserverBackup()\n"));

	iBackupAndRestoreObserver = aBackupAndRestoreObserver;
}

//----------------------------------------------------------------------------

void CEapserverBackup::ConstructL()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapserverBackup::ConstructL()")));
    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapserverBackup::ConstructL()\n"));

	iBackupOrRestoreInProgress = EFalse;
	User::LeaveIfError(iBackupProperty.Attach(KUidSystemCategory,KUidBackupRestoreKey));
	CActiveScheduler::Add(this);
	iBackupProperty.Subscribe(iStatus);
	SetActive();
}

//----------------------------------------------------------------------------

CEapserverBackup::~CEapserverBackup()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapserverBackup::~CEapserverBackup()")));
    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapserverBackup::~CEapserverBackup()\n"));

	Cancel();
	iBackupProperty.Close();
}

//----------------------------------------------------------------------------

void CEapserverBackup::DoCancel()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapserverBackup::DoCancel()")));
    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapserverBackup::DoCancel()\n"));

	iBackupProperty.Cancel();
}

//----------------------------------------------------------------------------

TBool CEapserverBackup::IsBackupOrRestoreInProgress()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapserverBackup::IsBackupOrRestoreInProgress()")));
    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapserverBackup::IsBackupOrRestoreInProgress()\n"));

	return iBackupOrRestoreInProgress;
}

//----------------------------------------------------------------------------

/**
 *  @leave KErrNotSupported if unknown backup flag is found
 */
void CEapserverBackup::RunL()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapserverBackup::RunL()")));
    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapserverBackup::RunL()\n"));

	iBackupProperty.Subscribe(iStatus);
	SetActive();


	TInt backupRestoreFlag;
	iBackupProperty.Get(backupRestoreFlag);

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapserverBackup::RunL(): backupRestoreFlag=0x%08x"),
		backupRestoreFlag));

	switch(backupRestoreFlag & KBURPartTypeMask)
	{
 		case EBURUnset:
 		case EBURNormal:
 			if(iBackupOrRestoreInProgress) //only report complete if already reported starting
 			{
				EAP_TRACE_DEBUG_SYMBIAN((_L("CEapserverBackup::RunL(): Backup or restore complete")));
 				iBackupAndRestoreObserver->BackupOrRestoreCompleteL();
 				iBackupOrRestoreInProgress=EFalse;
 			}
 			break;
 		case EBURBackupFull:
 		case EBURBackupPartial:
		case EBURRestoreFull:
		case EBURRestorePartial:
			{
				EAP_TRACE_DEBUG_SYMBIAN((_L("CEapserverBackup::RunL(): Backup or restore starts")));
				iBackupOrRestoreInProgress=ETrue;
				iBackupAndRestoreObserver->BackupOrRestoreStartingL();
			}
			break;
		default:
			User::Leave(KErrNotSupported); //unexpected value
	};
}

//----------------------------------------------------------------------------
// End of file.
