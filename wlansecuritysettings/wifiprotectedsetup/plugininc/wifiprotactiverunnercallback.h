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
* Description: Defines MActiveRunnerCallback interface
*
*/

/*
* %version: tr1cfwln#5 %
*/

#ifndef M_ACTIVERUNNERCALLBACK_H
#define M_ACTIVERUNNERCALLBACK_H
/**
 * MActiveRunnerCallback
 * callback interface to handle PIN query exit
 * @since S60 v3.2
*/
class MActiveRunnerCallback
    {
    public:
        /**
        * called when CWifiProtEnterPinDlg is finished
        * @param TInt aResponse can be KErrNone or KErrCancel
        */
        virtual void PinQueryExitL( TInt aResponse ) = 0;
    };
#endif //M_ACTIVERUNNERCALLBACK_H