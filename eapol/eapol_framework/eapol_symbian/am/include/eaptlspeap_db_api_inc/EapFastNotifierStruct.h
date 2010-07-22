/*
* Copyright (c) 2001-2006 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: %
*/

#ifndef EAPFASTNOTIFIERSTRUCT_H
#define EAPFASTNOTIFIERSTRUCT_H

const TUid KEapFastNotifierUid = {0x2000F8DF};

const TUint KMaxEapFastNotifierBufLength = 255;

enum EEapFastNotifierUiItem
{
	EEapFastNotifierPacStorePwQuery,         /* 0 */
	EEapFastNotifierWrongPacStorePwNote,     /* 1 */
	EEapFastNotifierAuthProvWaitNote,        /* 2 */
	EEapFastNotifierAuthProvWaitNoteEnd,     /* 3 */
	EEapFastNotifierUnauthProvWaitNote,      /* 4 */
	EEapFastNotifierUnauthProvWaitNoteEnd,   /* 5 */
	EEapFastNotifierInstallPacConfirmQuery,	 /* 6 */
	EEapFastNotifierProvSuccessNote,         /* 7 */
	EEapFastNotifierProvNotSuccessNote,      /* 8 */
	EEapFastNotifierPacFilePwQuery,          /* 9 */
	EEapFastNotifierWrongPacFilePwNote,      /* 10 */
	EEapFastNotifierCreateMasterkeyQuery,    /* 11 */
	EEapFastNotifierUiItemsNumber            /* 12 */ // keep always as last element
};

enum EEapFastNotifierUserAction
{
	EEapFastNotifierUserActionOk,
	EEapFastNotifierUserActionCancel
};

struct TEapFastNotifierStruct
{
	EEapFastNotifierUiItem iEapFastNotifierUiItem;
	TBuf<KMaxEapFastNotifierBufLength> iEapFastNotifierBuffer;
	EEapFastNotifierUserAction iEapFastNotifierUserAction;
};

#endif // EAPFASTNOTIFIERSTRUCT_H

// End of File
