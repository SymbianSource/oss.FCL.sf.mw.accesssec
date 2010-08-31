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
* Description:  EAP-server backup and restore.
*
*/

/*
* %version: 4 %
*/


#ifndef _EAP_SERVER_BACKUP_H_
#define _EAP_SERVER_BACKUP_H_

#include <e32base.h>
#include <e32property.h>

/**
 @file
*/

//------------------------------------------------------------------------------------------------

class AbsEapserverBackup
{

public:

	virtual void BackupOrRestoreCompleteL() = 0;

	virtual void BackupOrRestoreStartingL() = 0;
};

//------------------------------------------------------------------------------------------------

class CEapserverBackup
: public CActive
{

public:

	static CEapserverBackup* NewL(AbsEapserverBackup * const aBackupAndRestoreObserver);

	virtual ~CEapserverBackup();

	TBool IsBackupOrRestoreInProgress();

	CEapserverBackup(AbsEapserverBackup * const aBackupAndRestoreObserver);

	void ConstructL();

private:

	void RunL();

	void DoCancel();

private:

	AbsEapserverBackup * iBackupAndRestoreObserver;

	RProperty iBackupProperty;

	TBool iBackupOrRestoreInProgress;
};

#endif // _EAP_SERVER_BACKUP_H_

// End of file.
